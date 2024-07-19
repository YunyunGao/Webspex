// convert UTC timestamp to localtime
$( document ).ready(function()
{
    var nL = document.getElementsByClassName("datetime");
    var i;
    for (i = 0; i < nL.length; i++)
    {
        var tsDate = new Date(parseInt(nL[i].getAttribute('data-timestamp'), 10)*1000);
        nL[i].innerHTML = (tsDate.getFullYear() + '-' + (tsDate.getMonth()+1) + '-' + tsDate.getDate() + '   ' +
                           tsDate.getHours()    + ':' + tsDate.getMinutes()   + ':' + tsDate.getSeconds());
    }
})