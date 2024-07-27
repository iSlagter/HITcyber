$(document).ready(function() {
    function loadScripts() {
        $.getScript('https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js');
        $.getScript('https://cdn.jsdelivr.net/npm/chart.js');
        $.getScript('/static/script.js');
    }

    function updateTitle(data) {
        var newTitle = $(data).filter('title').text();
        $('title').text(newTitle);
    }

    function loadContent(url, addToHistory = true) {
        var $mainContent = $('#logged-main-content').length ? $('#logged-main-content') : $('#main-content');

        $mainContent.fadeOut(200, function() {
            $.get(url, function(data) {
                var newContent = $(data).find('#logged-main-content').html() || $(data).find('#main-content').html();
                $mainContent.html(newContent).fadeIn(200, function() {
                    loadScripts();
                });
                updateTitle(data);
                var flashMessages = $(data).find('.flash-messages').html();
                $('.flash-messages').html(flashMessages);
            });
        });

        if (addToHistory) {
            window.history.pushState({ path: url }, '', url);
        }
    }

    $(document).on('click', '.ajax-link', function(e) {
        e.preventDefault();
        var url = $(this).attr('href');
        loadContent(url);
    });

    $(document).on('submit', 'form', function(e) {
        e.preventDefault();
        var $form = $(this);
        $.ajax({
            type: $form.attr('method'),
            url: $form.attr('action'),
            data: $form.serialize(),
            success: function(response) {
                if (response.redirect) {
                    loadContent(response.redirect);
                    location.reload(false);
                } else {
                    var $mainContent = $('#logged-main-content').length ? $('#logged-main-content') : $('#main-content');
                    var newContent = $(response).find('#logged-main-content').html() || $(response).find('#main-content').html();
                    $mainContent.html(newContent);
                    updateTitle(response);
                    var flashMessages = $(response).find('.flash-messages').html();
                    $('.flash-messages').html(flashMessages);
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log('Error:', textStatus, errorThrown);
                alert('Failed to submit the form. Please try again.');
            }
        });
    });

    window.addEventListener('popstate', function(e) {
        if (e.state && e.state.path) {
            loadContent(e.state.path, false);
        }
    });
});
