#!/usr/bin/env python3

#
# Copyright (c) 2025 <sashan@openssl.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import json
import argparse
from jinja2 import Environment, FileSystemLoader
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates

#
# returns elements 1, 2, 3, 4
#
def json_list_filter(iterable):
	rv = ""
	for it in iterable[: -1]:
		rv = rv + str(it) + ", "

	rv = rv + str(iterable[-1])

	return rv

app: FastAPI = FastAPI()

templates = Jinja2Templates(directory="templates")
templates.env.filters["json_list"] = json_list_filter

#
# Functions here create 'API' between .json data which
# come from mprofile.so and the mprofile.py script which
# process those data. So instead of doing
#	mr_id = mr["id"]
# we will be doing
#	mr_id = get_id(mr)
# this should help us to minimize impact of changes to .json
# format in mprofile.so. Perhaps it is overcautious.
#
def is_realloc(mr):
	return mr["state"] == "realloc"

def is_alloc(mr):
	return mr["state"] == "allocated"

def is_free(mr):
	return mr["state"] == "free"

def get_addr(mr):
	return mr["addr"]

def get_realloc(mr):
	return mr["realloc"]

def get_delta_sz(mr):
	return mr["delta_sz"]

def set_delta_sz(mr, delta_sz):
	mr["delta_sz"] = delta_sz

def get_id(mr):
	return mr["id"]

def get_index(mr):
	return mr["id"] - 1

def get_operation(mr):
	return mr["state"]

def get_stackid(mr):
	return mr["stack_id"]

def get_nextid(mr):
	return mr["next_id"]

def get_previd(mr):
	return mr["prev_id"]

def set_nextid(mr, next_id):
	mr["next_id"] = next_id
	return

def set_previd(mr, prev_id):
	mr["prev_id"] = prev_id
	return

def get_trace(st):
	#
	# need to do slice. the json data we got from mprofile.so always
	# contains empty string there.
	#
	return st["stack_trace"][:-1]

def time_to_float(tr):
	return float(tr["s"]) + float(tr["ns"]/1000000000)

def get_timef(mr):
	return time_to_float(mr["time"])

def set_mem_current(mr, msize):
	mr["mem_current"] = msize 

def get_mem_current(mr):
	return mr["mem_current"]


#
# this is a class wrapper around mr dictionary for ninja template to separate
# templates from eventual changes on json done in.so
#
class MR:
	def __init__(self, mr):
		self._mr = mr

	def is_realloc(self):
		return is_realloc(self._mp)

	def is_alloc(self):
		return is_alloc(self._mr)

	def is_free(self):
		return is_free(self._mr)

	def get_addr(self):
		return get_addr(self._mr)

	def get_realloc(self):
		return get_realloc(self._mr)

	def get_delta_sz(self):
		return get_delta_sz(self._mr)

	def get_id(self):
		return get_id(self._mr)

	def get_operation(self):
		return get_operation(self._mr)

	def get_mem_current(self):
		return get_mem_current(self._mr)

class MProfile:
	#
	# traverse allocation chain back to the first operation
	# in chain which causes the leak.
	#
	def __add_leak(self, mr):
		leak = mr
		while mr != None:
			leak = mr
			mr = self.get_prev(mr)
		self._leaks.append(leak)

	def __calc_current(self):
		mem_current = 0
		index = 0
		for mr in self._mem_records:
			mem_current = mem_current + get_delta_sz(mr)
			set_mem_current(mr, mem_current)

				
	def __create_profile(self, mem_records):
		return list(map(get_mem_current, mem_records))

	def __get_slice(self, min_id = -1, max_id = -1):
		def with_start_time():
			#
			# The allocation never happens at start time (time
			# zero).  To plot a chart starting at time zero we
			# create a zero allocation record at start time.
			#
			mem_records = [
				{
					"id": 0,
					"addr" : 0,
					"realloc": 0,
					"delta_sz": 0,
					"mem_current": 0,
					"state": "allocated",
					"next_id": 0,
					"prev_id": 0,
					"stack_id": 0,
					"timme": self._start_time
				}
			]
			mem_records = mem_records + self._mem_records
			return mem_records
		try:
			if min_id == -1 and max_id == -1:
				return with_start_time()
			elif min_id < max_id:
				if min_id == -1:
					return with_start_time()
				else:
					rv = self._mem_records[min_id : max_id]
					return rv
			elif max_id == -1:
				return self._mem_records[min_id : ]
			else:
				return [] # or None, don't know what's better
		except IndexError:
			return [] # or None, don't know what's better

	def __get_samples(self, mem_records):
		slice_size = int(len(mem_records)/self._sample_sz)
		if slice_size == 0:
			return mem_records
		mem_records_slices = [ self._mem_records[i : i + slice_size ]
		    for i in range(0, len(mem_records), slice_size) ]
		return map(lambda x: max(x,\
		    key = lambda k : get_mem_current(k)), mem_records_slices)
	#
	# retrieve a record chain for allocation record ar.
	#
	def get_chain(self, ar):
		chain = []
		chain.append(ar)
		while get_nextid(ar) != 0:
			ar = self.get_mr(get_nextid(ar))
			chain.append(ar)
		return chain

	#
	# constructor receives a json data. json data is dictionary
	# which holds two lists:
	#	allocations (list of memory records (operations)
	#	stacks list of stack traces
	#
	# samples is the number of data samples we are going to present in
	# .html/www output.  We can expect ~1M of alloc/free/realloc records
	# in .json data. It's hard to present 1M of stacktraces or data points
	# in javascript charts. Therefore we only present a sample from entire
	# set.
	#
	def __init__(self, json_data, sample_sz = 100):
		self._leaks = None
		self._mem_records = json_data["allocations"]
		for mr in self._mem_records:
			set_mem_current(mr, 0)
		self._stacks = json_data["stacks"]
		#
		# call stacks in json data are dump of RB-tree,
		# we need to sort the array/list by 'id'
		#
		self._stacks.sort(key = lambda x : x["id"])
		self._start_time = json_data["start_time"]
		self.__calc_current()
		self._sample_sz = sample_sz
		self._annotation = json_data["annotation"]

	#
	# count allocation failures
	#
	def alloc_failures(self):
		return filter(
		    lambda x: True if is_alloc(x) and get_addr(x) == 0
			else False,
		    self._mem_records)

	#
	# count reallocation failures
	#
	def realloc_failures(self):
		return filter(
		    lambda x: True if is_realloc(x) and get_addr(x) == 0 and \
			get_size(x) > 0 else False, self._mem_records)

	def get_free_op(self, mr):
		next_mr = self.get_mr(get_nextid(mr))
		while next_mr != None:
			mr = next_mr
			next_mr = self.get_mr(get_nextid(mr))

		if mr != None and is_free(mr):
			return mr
		else:
			return None
			
	def is_leak(self, mr):
		if not is_alloc(mr):
			return False

		next_mr = self.get_mr(get_nextid(mr))
		while next_mr != None:
			mr = next_mr
			next_mr = self.get_mr(get_nextid(mr))

		return not is_free(mr)

	#
	# return list of memory leaks
	#
	def leaks(self):
		if self._leaks == None:
			leaks = filter(self.is_leak, self._mem_records)
			self._leaks = list(leaks)

		return self._leaks

	#
	# return the size of given memory leak
	#
	def get_leak_sz(self, leak_mr):
		leak_sz = get_delta_sz(leak_mr)
		next_mr = self.get_next(leak_mr)
		while next_mr != None:
			leak_mr = next_mr
			leak_sz = leak_sz + get_delta_sz(leak_mr)
			next_mr = self.get_next(leak_mr)
		return leak_sz

	#
	# return list of allocation operations
	#
	def alloc_ops(self):
		return filter(
		    lambda x: True if is_alloc(x) and get_addr(x) != 0
			else False,
		    self._mem_records)

	#
	# return list of reallocation operations
	#
	def realloc_ops(self):
		return filter(
		    lambda x: True if is_realloc(x) and get_addr(x) != 0
			else False,
		    self._mem_records)

	#
	# return list of all free (release) operations
	#
	def release_ops(self):
		f = filter(
		    lambda x: True if is_free(x) and get_addr(x) != 0
			else False,
		    self._mem_records)

	def all_ops(self):
		return self._mem_records

	#
	# get memory record for given id. returns None when
	# id not found
	# 
	def get_mr(self, op_id):
		if op_id < 1 or op_id > len(self._mem_records):
			return None
		op_id = op_id - 1
		return self._mem_records[op_id]

	#
	# get callstack for given memory record
	#
	def get_stack(self, mr):
		if mr == None or get_stackid(mr) == 0:
			return None
		return get_trace(self._stacks[get_stackid(mr) - 1])

	#
	# get next link in memory lifecycle chain
	#
	def get_next(self, mr):
		if get_nextid(mr) != 0:
			return self.get_mr(get_nextid(mr))
		else:
			return None

	#
	# get previous link in memory lifecycle chain
	#
	def get_prev(self, mr):
		if get_previd(mr) != 0:
			return self.get_mr(get_previd(mr))
		else:
			return None

	#
	# calculate total number of bytes allocated
	#
	def get_total_mem(self):
		alloc_sz = sum(map(lambda mr: 0 if get_delta_sz(mr) < 0 \
		    else get_delta_sz(mr), self._mem_records))
		return alloc_sz

	#
	# calculate total number of operations (malloc/realloc)
	# which allocate memory
	#
	def get_total_allocs(self):
		alloc_ops = sum(map(lambda mr: 1 if get_delta_sz(mr) > 0 else 0,
		    self._mem_records))
		return alloc_ops

	#
	# returns a memory profile which is list of memory allocated
	# at exact point of application lifetime
	#
	def get_profile(self):
		return [ 0 ] + list(map(lambda mr: get_mem_current(mr),\
		    self.__get_samples(self.__get_slice())))

	def get_profile_id(self):
		return [ 0 ] + list(map(lambda mr: get_id(mr),
		    self.__get_samples(self.__get_slice())))

	def get_time_axis(self, mem_records_it = None):
		if mem_records_it == None:
			mem_records_it = self.__get_samples(self._mem_records)

		t = [ float(0) ]
		for mr in mem_records_it:
			t.append((get_timef(mr) - \
			    time_to_float(self._start_time)) * 1000000)

		return t

	def get_profile_json(self, min_id = -1, max_id = -1):
		mem_records_slice = self.__get_slice(min_id, max_id)
		mem_records_it = self.__get_samples(mem_records_slice)

		#
		# __get_samples() returns map iterator. To instatiate a list
		# from iterator one does: list(samples_it)
		#
		rv = {
			"profile" : list(mem_records_it),
			"xxaxis" : self.get_time_axis(mem_records_it)
		}
		return rv

	def get_top_memory(self, min_id = -1, max_id = -1):
		mem_records_slice = self.__get_slice(min_id, max_id)
		mrecord = max(mem_records_slice,\
		    key = lambda k: get_mem_current(k))
		rv = {
			"top_memory_sz" : get_mem_current(mrecord)
		}
		return rv

	def get_top_alloc(self, min_id = -1, max_id = -1):
		mem_records_slice = self.__get_slice(min_id, max_id)
		mrecord = max(mem_records_slice,\
		    key = lambda k: get_delta_sz(k))
		stack_trace = None

		if get_delta_sz(rv) < 1:
			return None

		rv = {
		    "top_record_sz" : get_delta_sz(rv),
		    "top_record_time" : get_timef(rv) - self._start_time,
		    "top_record_stack" : self._stacks[get_stackid(mr)]["stack_trace"]
		}
		try:
			stack_trace = self._stacks[get_stackid(mr)]
			rv["top_record_stack"] = stack_trace["stack_record_trace"]
		except KeyError:
			rv["top_record_stack"] = []

		return rv

	def get_top_free(self, min_id = -1, max_id = -1):
		mem_records_slice = self.__get_slice(min_id, max_id)
		mrecord = min(mem_records_slice,\
		    key = lambda k: get_delta_sz(k))
		stack_trace = None

		if get_delta_sz(rv) > -1:
			return None

		rv = {
		    "top_record_sz" : get_delta_sz(rv),
		    "top_record_time" : get_timef(rv) - self._start_time,
		    "top_record_stack" : self._stacks[get_stackid(mr)]["stack_trace"]
		}
		try:
			stack_trace = self._stacks[get_stackid(mr)]
			rv["top_record_stack"] = stack_trace["stack_trace"]
		except KeyError:
			rv["top_record_stack"] = []

		return rv


	def get_mem_peak(self):
		return max(self._mem_records,
		    key = lambda k : get_mem_current(k))	

	def get_max_peak(self):
		return get_mem_current(self.get_mem_peak())
		
	def get_max_buf(self):
		op = max(self._mem_records,
		    key = lambda k : get_delta_sz(k))	
		return get_delta_sz(op)

	def get_stack_json(self, record_id):
		stack_trace = None
		try:
			mr = self._mem_records[record_id]
			stack = self._stacks[get_stackid(mr)]
			stack_trace = stack["stack_trace"]
		except (IndexError, KeyError):
			stack_trace = []

		rv = {
			"record_stack" : stack_trace
		}
		return rv

	def check(self):
		test = 1
		for mr in self._mem_records:
			if get_id(mr) != test:
				print("Expected {0} for {1}".format(test,
				    get_id(mr)))
			test = test + 1

	def get_annotation(self):
		return self._annotation

	#
	# return list of memory buffers which
	# are still alive w.r.t. `op`. The `op`
	# serves as a time marker.
	#
	def live_memory(self, op):
		allocations = filter(lambda x: \
		    True if get_id(x) < get_id(op) else False,
		    self.get_allocations())
		live_allocs = []
		for a in allocations:
			f = get_free_op(self, a)
			#
			# if free operation happens after
			# op, then  memory allocated by
			# `a` is still alive w.r.t. `op`
			if get_id(f) > get_id(op):
				live_allocations.append(a)
			
		return live_allocations

	def get_live_chain(self, alloc_op, point_op):
		chain = [alloc_op]
		next_op = get_nextid(alloc_op)
		while next_op != None and get_id(next_op) < get_id(point_op):
			chain.append(next_op)
			next_op = get_nextid(next_op)
		return chain

	def get_live_sz(self, alloc_op, point_op):
		live_chain = get_live_chain(self, alloc_op, point_op)
		return sum(map(get_delta_sz, live_chain))

	def get_time(self, mp):
		return (get_timef(mp) - self._start_time) * 1000000


def create_parser():
	parser = argparse.ArgumentParser()
	parser.add_argument("json_files",
	    type = str,
	    help = "mprofile json data",
	    action="extend", nargs="+")
	parser.add_argument("-v", "--verbose", action = "store_true")
	parser.add_argument("-l", "--leaks", help = "report memory leaks",
	    action = "store_true")
	parser.add_argument("-a", "--allocated", help = "report all memory allocated",
	    action = "store_true")
	parser.add_argument("-t", "--title", help = "report title",
	    default = "Memory Profile")
	parser.add_argument("-m", "--max", help = "report max mem usage",
	    action = "store_true")
	parser.add_argument("-s", "--server",
	    help = "serve .html on http://localhost:8000",
	    action = "store_true")
	parser.add_argument("-f", "--file",
	    help = "file with script used to obtain data"),
	parser.add_argument("-c", "--check",
	    help = "check the source data and report errors",
	    default = "store_true")

	return parser

def report_leaks(mp, parser_args):
	leaks = mp.leaks()
	if len(leaks) == 0:
		print("There are no leaks")
		return

	print("{0} bytes lost in {1} leaks".format(
	    sum(map(lambda x: mp.get_leak_sz(x), leaks)), len(leaks)))

	if parser_args.verbose:
		e = Environment(loader = FileSystemLoader("templates/"))
		t = e.get_template("leaks.txt")
		context = {
			"MR" : MR,
			"mp" : mp 
		}
		output = t.render(context)
		print(output)
	return

def report_mem_total(mp, parser_args):
	print("Total memory allocated: {0} in {1} operations".format(
	    mp.get_total_mem(), mp.get_total_allocs()))
	return

profiles = None
parser_args = None

@app.get("/", response_class = HTMLResponse)
def html_report(request: Request):
	t = Jinja2Templates(directory="templates")
	t.env.filters["json_list"] = json_list_filter
	global parser_args
	global profiles
	if (len(profiles) == 1):
		context = {
			"title" : parser_args.title,
			"mp" : profiles[0],
			"MR" : MR,
			"leak_count" : len(profiles[0].leaks()),
			"lost_bytes" : sum(map(\
			    lambda x: profiles[0].get_leak_sz(x), \
			    profiles[0].leaks()))
		}
		return t.TemplateResponse(request = request, \
		    name = "report.html", context = context)
	else:
		context = {
			"title" : parser_args.title,
			"profiles" : profiles,
			"MR" : MR,
			"script" : parser_args.file,
		}
		return t.TemplateResponse(request = request, \
		    name = "compare.html", context = context)

@app.get("/favicon.ico", response_class = FileResponse)
def favicon():
	return FileResponse("www-resources/favicon.ico")

@app.get("/get_mprofile/{profile_id}/{min_id}/{max_id}")
def get_mprofile(profile_id, min_id = -1, max_id = -1):
	if profile_id < 0 or len(profiles) < profile_id:
		return { 'mprofile' : [], "xaxxis": [] }

	mp = profiles[profile_id]
	return mp.get_mprofile(min_id, max_id)

@app.get("/get_max_mem/{profile_id}/{min_id}/{max_id}")
def get_max_mem(profile_id, min_id = -1, max_id = -1):
	if profile_id < 0 or len(profiles) < profile_id:
		return { 'mprofile' : [], "xaxxis": [] }

	mp = profiles[profile_id]
	return mp.get_maxmem(min_id, max_id)

@app.get("/get_top_alloc/{profile_id}/{min_id}/{max_id}")
def get_top_alloc(profile_id, min_id = -1, max_id = -1):
	if profile_id < 0 or len(profiles) < profile_id:
		return { 'top_record' : None }
	mp = profiles[profile_id]
	return mp.get_top_alloc(min_id, max_id)

@app.get("/get_top_free/{profile_id}/{min_id}/{max_id}")
def get_top_free(profile_id, min_id = -1, max_id = -1):
	if profile_id < 0 or len(profiles) < profile_id:
		return { 'top_record' : None }
	mp = profiles[profile_id]
	return mp.get_top_free(min_id, max_id)

@app.get("/get_stack/{profile_id}/{record_id}")
def get_stack(profile_id, record_id):
	profile_id = int(profile_id)
	if profile_id < 0 or len(profiles) < profile_id:
		return { 'record_stack' : [] }
	mp = profiles[profile_id]
	return mp.get_stack_json(int(record_id))
	
def launch_server(args):
	global parser_args
	parser_args = args
	uvicorn.run(app)

if __name__ == "__main__":
	e = Environment()
	e.filters["json_list"] = json_list_filter
	parser = create_parser()
	args = parser.parse_args()
	if args.json_files == None:
		parser.usage()

	profiles = [ MProfile(json.load(open(f))) for f in args.json_files ]
	e = Environment(loader = FileSystemLoader("templates/"))
	t = e.get_template("compare.html")

	if args.check == True:
		for p in profile:
			p.check()

	if args.server:
		launch_server(args)
	else:
		if args.allocated:
			report_mem_total(mp, args)

		if args.leaks:
			report_leaks(mp, args)

		if args.max:
			print(get_mem_current(mp.get_mem_peak()))
