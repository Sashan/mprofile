{#
mem_profile_chart() macro generates javascript function which
creates an apex chart. Argument are as follows:
    - name:  name of the javascript function
    - chart_elm_id: html element id where to attach chart,
      should be <div id='...'>
    - cstack_elm_id: html element id where to show callstack
      associated with data point on chart, should be <div id='...'>
#}
{% macro mem_profile_chart(name, chart_elm_id = 'chart', cstack_elm_id='mem-trace-', profile_id = 0) %}

{#
this is a callback to show/hide callstack associated with datapoint
#}
function show_stack(elm_id, stack_json)
{
    const div = document.getElementById(elm_id);

    if (div != null) {
	const ul = document.createElement('ul');

	ul.classList.add('stack-trace');

	for (const frame of stack_json.record_stack) {
	    const li = document.createElement('li')
	    const content = document.createTextNode(frame)
	    li.appendChild(content);
	    ul.appendChild(li);
	}

	const old_ul = div.firstChild;
	if (old_ul != null) {
	    div.replaceChild(ul, old_ul);
	} else {
	    div.appendChild(ul);
	}
    }
}

var record_id_{{ name }} = [ {{ m }} ];
var record_id_set_{{ name }} = [ {{ mp.get_profile_id()|json_list }} ];
async function select_stack_{{ name }}(event, chartContext, opts)
{
    var url = '/get_stack/{{ profile_id }}/' + 
	record_id_set_{{ name }}[opts.dataPointIndex] + '/';
    const response = await fetch(url);
    const stack_json = await response.json();

    show_stack('mem-trace', stack_json);
}

{#
this initializes apex chart. it is based on tutorial
here:
    https://www.explo.co/chart-library-tutorials/apexcharts-javascript-tutorial
the referene documentaton for apex charts is here:
    https://www.apexcharts.com/docs
#}
function {{ name }}()
{
    var chart_opts = {
	chart: { 
	    height: 450,
	    width: 900,
	    type: 'line',
	    events: {
		dataPointSelection: select_stack_{{ name }}
	    }
	},
	series: [
	    {
	    name: '{{ mp.get_annotation() }}',
	    data: [ {{ mp.get_profile()|json_list }} ]
	}],
	xaxis: {
	    categories: [ {{ mp.get_time_axis()|json_list }} ],
	    title: {
		text: 'Time'
	    }
	},
	tooltip: {
	    {#
	    we need to set these to get callback working, see 
	    https://www.apexcharts.com/docs/options/chart/events/
	    search for dataPointSelection
	    #}
	    intersect: true,
	    shared: false
	},
	markers: {
	    size: 1 {# size must be at least 1, to make dataPointSelection wokring. selecting 3 mkes chart rendering to fail ?bug? #}
	}
    }

    var chart = new ApexCharts(document.querySelector("#" + "{{ chart_elm_id }}"), chart_opts);
    chart.render();
}
{% endmacro %}
