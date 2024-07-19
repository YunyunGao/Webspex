// allow non-js users to upload files by disabling the button using js
$(document).ready(function()
{
    $('.disabled').prop("disabled",true);
});

function enable_upload(id)
{
    document.getElementById(id).disabled = false;
}