function onerrorImg(id)
{
    $(id).remove();
}

$(function()
{
    function pollCout(scroll = true)
    {
        $.getJSON(
            '/ajax/{{ id }}',
            {}, // get/post dict
            function(data) // callback
            {
                $("#cout").text(data.cout);
                if (scroll)
                {
                    $("#cout").scrollTop($("#cout")[0].scrollHeight);
                }
                
                if (data.status < 0)
                {
                    $("#jobstatus").text('Job status: Failure.');
                    $("#throbber").replaceWith('');
                }
                else if (data.status >= 3)
                {
                    $("#throbber").replaceWith(''); //('<span id="throbber">(Done)</span>');
                    $("#jobstatus").text('Job status: Success.');
                    //$("#result-head").append('Results:<small>(click on picture for a high resolution view)</small><br>');

                    $("#plots").append('<div id="pint"><h3>Intensities:</h3> (click on picture for higher resolution)<img src="{{ url_for('intensities', id=id) }}" alt="Loading..." class="plot" onclick="showModal(\'int\')" onerror="onerrorImg(\'#pint\')"/><hr /></div>');
                    $("#plots").append('<div id="pamp"><h3>Amplitudes:</h3> (click on picture for higher resolution)<img src="{{ url_for('amplitudes', id=id) }}" alt="Loading..." class="plot" onclick="showModal(\'amp\')" onerror="onerrorImg(\'#pamp\')"/></div>');

                    $("#m_amp").append('<a href="{{ url_for('amplitudes', id=id) }}"><img src="{{ url_for('amplitudes', id=id) }}" alt="" class="plot"/></a>');
                    $("#m_int").append('<a href="{{ url_for('intensities', id=id) }}"><img src="{{ url_for('intensities', id=id) }}" alt="" class="plot"/></a>');

                    $("#redoform").after('<p class="center-text"><em>Suprised?</em> To see examples of different pathologies: <a href="{{ url_for('pathol') }}"><span class="click-here">click here</span></a></p>');
                    $("#redoform").css('display', 'block');
                }
                else
                {
                    if (data.status == 1)
                        $("#jobstatus").text('Job status: Queued.');
                    else if (data.status == 2)
                        $("#jobstatus").text('Job status: Running.');
                        
                    setTimeout(pollCout, 5000);
                }
            }
        );
    }
    pollCout(false);
});