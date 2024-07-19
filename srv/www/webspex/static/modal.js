// reveal selected modal
function showModal(id)
{
    //history.pushState({id: id}, '', window.location.pathname + id);
    $('.modal-content').css('display', 'none'); // hide all open modals
    $('.modal').css('display', 'block');
    $('#m_' + id).css('display', 'block');
}

// When the user clicks on <span> (x) or outside of the modal, hide all modals
function hideModal()
{
    $('.modal-content').css('display', 'none');
    $('.modal').css('display', 'none');
}

// push state for history
function pushModal(id)
{
    if (id)
    {
        history.pushState({id: id}, '', window.location.pathname + '#' + id);
        showModal(id);
    }
}

function popModal()
{
    if (history.state && history.state.id)
        history.back();
    else
        updateModal();
}

function updateModal()
{
    if (history.state) // use state if possible
    {
        var id = history.state.id;
        showModal(id);
    }
    else if (window.location.hash.substr(1)) // get url anchor
    {
        var id = parseInt(window.location.hash.substr(1), 10)
        showModal(id);
    }
    else // fallback: just hide everything
    {
        hideModal();
    }
}

// open anchored modal when ready
$( document ).ready(function()
{
    //history.pushState({id: 'modal'}, '', window.location.href);
    var id = parseInt(window.location.hash.substr(1), 10);
    if (id) { showModal(id); }
})

// close modal when history is changed
window.onpopstate = function(event) { updateModal(); }

// close modal event
function closeModal(event)
{
    if (event.target.className == 'modal' || event.target.className == 'close')
    {
        popModal();
    }
}