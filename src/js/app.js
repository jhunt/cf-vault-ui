(function ($, document, window, undefined) {
  $.keys = function (object) {
    var l = [];
    for (key in object) { l.push(key); }
    return l.sort()
  };

  var api = function (method, url, data, opts) {
    return $.ajax($.extend(opts, {
      type:        method,
      url:         url,
      data:        JSON.stringify(data),
      processData: false,
      contentType: 'application/json'
    }));
  };

  window.rand = function (n) {
    var s = [];
    var alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"+
                "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"+
                "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"+
                "!\"#$%&'()*+,-./:;<=>?@{|}~[\\]^_`";
    var fn = ('crypto'   in window) ? window.crypto
           : ('msCrypto' in window) ? window.msCrypto
           : undefined;

    if (fn) {
      /* crypto-secure rng; use it! */
      var buf = new Uint8Array(n)
      fn.getRandomValues(buf)
      for (var i = 0; i < n; i++) {
        s[i] = alpha[buf[i] % alpha.length];
      }
    } else {
      for (var i = 0; i < n; i++) {
        s[i] = alpha[parseInt(Math.random() * alpha.length)];
      }
    }
    return s.join('');
  };

  $(function () {
    $(document)
    .on('click', 'body', function (event) {
      if ($('#modal').is(':visible')) {
        $('#modal').hide();
      } else {
        var $t = $(event.target);
        if (!$t.is('.modal, .modal *')) {
          $('.modal').hide();
        }
        if ($t.is('.modal a') && !$t.is('.control.menu a')) {
          $('.modal').hide();
        }
      }
    })
    .on('click', 'header a[rel="new"]', function (event) {
      event.preventDefault();
      event.stopPropagation();
      $(event.target).next('.menu').toggle();
    })
    .on('click', '.radio li', function (event) {
      var $radio = $(event.target).closest('.radio');
      $radio.find('li').removeClass('selected');
      $(event.target).addClass('selected');
    })
    .on('keyup', 'input', function (event) {
      if (event.keyCode == 13) {
        event.preventDefault();
        var $fields = $(event.target).closest('form')
                                     .find('input, textarea');
        var $next = $fields.eq($fields.index($(event.target))+1);
        $next.focus();
      }
    })
    .on('keyup', '.new input', function (event) {
      var $ctl = $(event.target);
      if ($ctl.val() == '') { return; }
      var $cur = $ctl.closest('.new');
      var $add = $cur.clone();
      $cur.removeClass('new');
      $add.find('input').each(function (i,e) { $(e).val(''); });
      if ($cur.is('.key-value')) {
        $cur.addClass('shown');
        $cur.addClass('single');
      }
      $add.insertAfter($cur);
    })
    .on('change', '.valid-for input', function (event) {
      var $ctl = $(event.target);
      var $cur = $ctl.closest('li');
      var val = $ctl.val();
      if (val == '' && $cur.siblings('li').length > 0) {
        $cur.remove();
        return;
      }
      $cur.find('.tag').remove();
      if (val.match(/^\d+\.\d+\.\d+\.\d+$/)) {
        $cur.append('<span class="tag">ip</span>');
      } else if (val.match(/@/)) {
        $cur.append('<span class="tag">email</span>');
      } else {
        $cur.append('<span class="tag">dns</span>');
      }
    })
    .on('change', '.key-value input.key', function (event) {
      var $ctl = $(event.target);
      var $cur = $ctl.closest('li');
      var kval = $cur.find('.key').val();
      var vval = $cur.find('.val').val();
      if (kval == '' && vval == '' && $cur.siblings('li').length > 0) {
        $cur.remove();
        return;
      }
    })

    .on('click', 'a[rel^="new:"]', function (event) {
      event.preventDefault();

      var type = $(event.target).attr('rel').replace(/^new:/,'');
      switch (type) {
      case 'secret':
        $('#m').template('new-secret');
        break;

      case 'cert':
      case 'ca':
        $('#m').template('new-x509', {type:type});
        break;

      case 'ssh':
      case 'rsa':
        $('#m').template('new-keypair', {type:type});
        break;
      }
    })
    .on('click', 'header img', function (event) {
      event.preventDefault();
      $('#m').template('home');
    })
    .on('click', '.key-value a.widget', function (event) {
      event.preventDefault();
      var $menu = $('.control.menu');
      var $ctl  = $(event.target).closest('.key-value');

      if ($menu.is(':visible')) {
        $(document.body).append($menu);
      } else {
        $menu.removeAttr('style');
        $ctl.append($menu);
      }
      event.stopPropagation();
      event.stopImmediatePropagation();
    })
    .on('click', '.key-value .control.menu', function (event) {
      var $t = $(event.target);
      if (!$t.is('a[rel]')) { return; }

      var $ctl = $t.closest('.key-value');
      var reclass = function (then, now) {
        $ctl.removeClass(then).addClass(now);
      };

      event.preventDefault();
      switch ($t.attr('rel')) {
      case 'mod:rand':
        $ctl.find('input.val').val(rand(32));
        break;

      case 'mod:single':
        reclass('multi', 'single');
        var v = $ctl.find('textarea').val();
        var $field = $('<input type="password" class="val">');
        $field.val(v);
        reclass('shown', 'hidden');

        $ctl.find('textarea').remove();
        $field.insertAfter($ctl.find('input'));
        break;

      case 'mod:multi':
        reclass('single', 'multi');
        var v = $ctl.find('input.val').val();
        var $field = $('<textarea class="val">');
        $field.val(v);

        reclass('hidden', 'shown');

        $ctl.find('input.val').remove();
        $field.insertAfter($ctl.find('input'));
        break;

      case 'reveal:hide':
        $ctl.find('input.val').attr('type', 'password');
        reclass('shown', 'hidden');
        break;

      case 'reveal:show':
        $ctl.find('input.val').attr('type', 'text');
        reclass('hidden', 'shown');
        break;

      case 'reveal:large':
        var v = $ctl.find('input.val').val();
        var p = $ctl.closest('form').find('input[name=path]').val();
        $('#modal').template('reveal', { path: p, secret: v });
        $('#modal').show();
        event.stopPropagation();
        event.stopImmediatePropagation();
        break;

      case 'pb:copy':
        break;
      default:
        console.log('unhandled control-menu target: %s', $t.attr('rel'));
        break;
      }
    })


    .on('submit', 'form.update', function (event) {
      event.preventDefault();
      var $form = $(event.target),
           type = $form.attr('data-type'),
           path = $form.find('[name=path]').val().replace(/\/+/, '/')
                                                 .replace(/^\//, '')
                                                 .replace(/\/$/, '');
              d = { type: type };

      if (path == "") {
        $form.find('.errors')
          .show()
          .template('errors', [
            'Please specify a path for this secret'
          ]);
        return;
      }

      switch (type) {
      case 'ssh':
      case 'rsa':
        d[type] = {
          bits: parseInt($form.find('.bits-for .selected').attr('data-value'))
        };
        break;

      case 'cert':
      case 'ca':
        var sans = [];
        $form.find('.valid-for input[type=text]').each(function (i,e) {
          if ($(e).is('.new.valid-for *')) { return; }
          sans.push($(e).val().trim());
        });
        if (sans.length == 0) {
          $form.find('.errors')
            .show()
            .template('errors', [
              'Please specify one or more valid-for names'
            ]);
          return;
        }

        var ttl = $form.find('.expires-in [name=ttl_num]').val();
        if (!ttl.match(/^\d+$/) || parseInt(ttl) < 1) {
          $form.find('.errors')
            .show()
            .template('errors', [
              'Please specify a positive, non-zero expiry'
            ]);
          return;
        }

        d.x509 = {
          subject: $form.find('input[name=subject]').val(),
          issuer:  $form.find('.signed-by input').val(),
          ttl:     ttl+$form.find('.expires-in .selected').text(),
          sans:    sans,
          ca:      type == "ca"
        };
        break;

      case 'secret':
        var n = 0;
        d.secret = {};
        $form.find('.key-value').each(function (i,e) {
          if ($(e).is('.new.key-value')) { return; }
          var k = $(e).find('input.key').val().trim();
          if (k == "") { return }
          d.secret[k] = $(e).find('input.val, textarea').val().trim();
          n++
        });
        if (n == 0) {
          $form.find('.errors').show().template('errors', [
            'You may want to specify some secret keys and values...'
          ]);
          return;
        }
        break;
      }

      $form.find('button').text('Saving...').prop('disabled', true);
      api('PUT', '/v1/secret/' + path, d, {
        success: function (secret) {
          $('#m').template('secret', secret);
        }
      });
    })


    .on('submit', '#search form', function (event) {
      event.preventDefault();
      var q = $(event.target).find('input[name=q]')
                             .val().trim();
      if (q != "") {
        api('GET', '/v1/secret?q='+encodeURIComponent(q), undefined, {
          success: function (results) {
            $('#m .search-render').template('search-results', { results: results });
          }
        });
      }
    })


    .on('click', 'a[href^="/secret/"]', function (event) {
      event.preventDefault();
      var path = $(event.target).attr('href').replace(/^\/secret\//, '');

      api('GET', '/v1/secret/'+path, undefined, {
        success: function (secret) {
          $('#m').template('secret', secret);
        }
      });
    });

    $('header img').click();

    api('GET', '/v1/secret/users/admin', undefined, {
      success: function (secret) {
        $('#m').template('secret', secret);
      }
    });
  });
})(jQuery, document, window);
