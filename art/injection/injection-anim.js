/**
 * Animation de marque « injection » — implémentation web de référence.
 *
 * La seringue entre, pique, la marque jaillit du point d'injection, puis s'y
 * résorbe. Le cycle est FERMÉ : l'état à 3000 ms est exactement l'état à 0 ms,
 * donc la boucle ne montre aucun raccord et peut tourner des heures.
 *
 * Ce fichier est utilisé tel quel à deux endroits :
 *   - la page de réglage `index.html` (barre d'outils, fonds, ralenti) ;
 *   - Kosp Injection (`ui/injection-anim.js`), pendant toute l'injection.
 * Le portage React Native de twitninfbeta suit la même chronologie
 * (`src/components/LogoInjectionAnimation.tsx`) : toute retouche de timing ici
 * doit y être reportée.
 *
 * Les deux chemins `assets/*.svg` sont remplacés par des data-URI à la
 * construction (`build.ps1`) : le fichier livré ne dépend d'aucun réseau et
 * passe la politique de sécurité de contenu de l'app (`img-src 'self' data:`).
 */
(function (global) {
  'use strict';

  var LOGO_SRC = 'assets/logo.svg';
  var SYRINGE_SRC = 'assets/syringe.svg';

  /* ================================================================
     CHRONOLOGIE (ms) — cycle de 3000 ms

       0 →  430   la seringue fend l'écran depuis le haut-droite
     430 →  560   anticipation : elle se ramasse
     560 →  720   coup de piston
     720          IMPACT — deux flashs, secousse, 4 ondes, 16 rayons,
                  24 gouttes, 12 étincelles
     720 →  880   le piston s'enfonce (compression sur l'axe)
     730 → 1380   la marque jaillit (squash & stretch + ouverture)
     760 → 1900   le produit diffuse dans la marque
     880 → 1440   la seringue se rétracte et sort du cadre
    1300 → 2160   halo d'énergie puis balayage de reflet
    2340 → 2760   sortie : la marque se résorbe dans le point d'injection
    2760 → 3000   respiration avant la boucle
     ================================================================ */
  var CYCLE = 3000;
  var IMPACT = 720;
  var OUTRO = 2340;

  /** La scène est calculée en unités de 720 px, puis mise à l'échelle. */
  var BASE = 720;

  var PAL = ['#16F8EF', '#11E7F6', '#1DD5F9', '#31BEFB', '#4AAAFC', '#5496FB', '#6682FB', '#7768FA', '#9544FB'];

  var E = {
    out: 'cubic-bezier(.16,.9,.3,1)',
    outSoft: 'cubic-bezier(.25,.8,.35,1)',
    in: 'cubic-bezier(.55,.06,.85,.32)',
    back: 'cubic-bezier(.34,1.56,.5,1)',
    spring: 'cubic-bezier(.22,1.4,.36,1)',
    burst: 'cubic-bezier(.07,.75,.22,1)',
    lin: 'linear',
  };

  var CSS = [
    // Trois niveaux, et ils ne sont pas interchangeables : `inj-fit` est la
    // boîte de mise en page (c'est elle qui fait la taille demandée),
    // `inj-scale` porte la mise à l'échelle — une transformation ne change pas
    // l'encombrement, mettre les deux sur le même élément le réduit d'autant —
    // et `inj-stage` garde sa transformation propre pour la secousse d'impact.
    '.inj-fit{pointer-events:none}',
    '.inj-fit.inj-clip{overflow:hidden}',
    '.inj-scale{transform-origin:top left;width:720px;height:720px}',
    '.inj-stage{position:relative;width:720px;height:720px;isolation:isolate}',
    '.inj-stage>*{position:absolute;pointer-events:none}',

    '.inj-logo-wrap{left:50%;top:50%;width:500px;height:500px;',
    'margin-left:-250px;margin-top:-264px;opacity:0;z-index:3;will-change:clip-path,opacity}',
    '.inj-logo-inner{position:absolute;inset:0;transform-origin:50% 52.8%;will-change:transform}',
    '.inj-logo{width:100%;height:100%;display:block}',

    '.inj-fluid{position:absolute;inset:0;opacity:0;transform-origin:50% 52.8%;',
    'mix-blend-mode:screen;will-change:transform,opacity;',
    'background:radial-gradient(circle at 50% 52.8%,#fff 0%,#16F8EF 16%,#31BEFB 38%,#5496FB 58%,#7768FA 78%,#9544FB 100%);',
    '-webkit-mask-size:100% 100%;mask-size:100% 100%;',
    '-webkit-mask-repeat:no-repeat;mask-repeat:no-repeat}',

    '.inj-shine-wrap{position:absolute;inset:0;overflow:hidden;',
    '-webkit-mask-size:100% 100%;mask-size:100% 100%;',
    '-webkit-mask-repeat:no-repeat;mask-repeat:no-repeat}',
    '.inj-shine{position:absolute;top:-40%;left:0;width:30%;height:180%;opacity:0;filter:blur(7px);',
    'background:linear-gradient(90deg,transparent,rgba(255,255,255,.95),transparent);',
    'transform:translateX(-200%) rotate(18deg)}',

    '.inj-halo{left:50%;top:50%;width:640px;height:640px;margin:-320px 0 0 -320px;',
    'border-radius:50%;z-index:1;opacity:0;filter:blur(14px);',
    'background:radial-gradient(circle,rgba(49,190,251,.55) 0%,rgba(119,104,250,.34) 38%,rgba(149,68,251,.14) 60%,rgba(149,68,251,0) 72%)}',

    '.inj-syringe{left:50%;top:50%;width:520px;height:520px;',
    'margin-left:-106.6px;margin-top:-435.2px;transform-origin:20.5% 83.7%;',
    'opacity:0;z-index:6;will-change:transform,opacity,filter}',

    '.inj-flash{left:50%;top:50%;width:420px;height:420px;margin:-210px 0 0 -210px;',
    'border-radius:50%;opacity:0;z-index:5;',
    'background:radial-gradient(circle,rgba(255,255,255,.98) 0%,rgba(255,255,255,.6) 34%,rgba(255,255,255,0) 70%)}',
    '.inj-flash-c{left:50%;top:50%;width:560px;height:560px;margin:-280px 0 0 -280px;',
    'border-radius:50%;opacity:0;z-index:2;filter:blur(6px);',
    'background:radial-gradient(circle,rgba(22,248,239,.75) 0%,rgba(84,150,251,.45) 34%,rgba(149,68,251,0) 68%)}',

    '.inj-ring{left:50%;top:50%;width:150px;height:150px;margin:-75px 0 0 -75px;',
    'border-radius:50%;opacity:0;z-index:5}',
    '.inj-ray{left:50%;top:50%;height:9px;width:190px;margin-top:-4.5px;',
    'border-radius:9px;transform-origin:0 50%;opacity:0;z-index:4}',
    '.inj-drop{left:50%;top:50%;border-radius:50%;opacity:0;z-index:4}',
    '.inj-spark{left:50%;top:50%;height:3px;border-radius:3px;transform-origin:0 50%;opacity:0;z-index:4}',
    '.inj-streak{left:50%;top:50%;height:5px;border-radius:5px;transform-origin:0 50%;opacity:0;z-index:2;',
    'background:linear-gradient(90deg,rgba(110,150,255,0),rgba(110,150,255,.6))}',
  ].join('');

  var styleInjected = false;
  function injectStyle() {
    if (styleInjected) return;
    styleInjected = true;
    var tag = document.createElement('style');
    tag.textContent = CSS;
    document.head.appendChild(tag);
  }

  /** Aléatoire à graine : la boucle est identique à chaque tour et d'une
   *  exécution à l'autre — une éclaboussure qui change de forme se remarque. */
  function seeded(seed) {
    var s = seed >>> 0;
    return function () {
      s = (s * 1664525 + 1013904223) >>> 0;
      return s / 4294967296;
    };
  }

  function div(parent, cls, css) {
    var el = document.createElement('div');
    el.className = cls;
    if (css) Object.assign(el.style, css);
    parent.appendChild(el);
    return el;
  }

  /**
   * Monte une scène dans `host`.
   *
   * @param {HTMLElement} host      conteneur (vidé au montage)
   * @param {object}      [opts]
   * @param {number}      [opts.size=720]   côté affiché, en px
   * @param {boolean}     [opts.loop=true]  boucle sans fin
   * @param {boolean}     [opts.clip=false] coupe ce qui déborde de la scène
   * @param {number}      [opts.rate=1]     vitesse de lecture
   */
  function create(host, opts) {
    opts = opts || {};
    injectStyle();

    var fit = div(host, 'inj-fit' + (opts.clip ? ' inj-clip' : ''));
    var scale = div(fit, 'inj-scale');
    var stage = div(scale, 'inj-stage');

    var flashC = div(stage, 'inj-flash-c');
    var halo = div(stage, 'inj-halo');

    var logoWrap = div(stage, 'inj-logo-wrap');
    var logoInner = div(logoWrap, 'inj-logo-inner');
    var logoImg = document.createElement('img');
    logoImg.className = 'inj-logo';
    logoImg.src = LOGO_SRC;
    logoImg.alt = '';
    logoInner.appendChild(logoImg);

    var maskUrl = 'url("' + LOGO_SRC + '")';
    var fluid = div(logoInner, 'inj-fluid', { webkitMaskImage: maskUrl, maskImage: maskUrl });
    var shineWrap = div(logoInner, 'inj-shine-wrap', { webkitMaskImage: maskUrl, maskImage: maskUrl });
    var shine = div(shineWrap, 'inj-shine');

    var rings = [
      div(stage, 'inj-ring', { border: '6px solid ' + PAL[3] }),
      div(stage, 'inj-ring', { border: '4px solid ' + PAL[8] }),
      div(stage, 'inj-ring', { border: '3px solid ' + PAL[0] }),
    ];
    var ringIn = div(stage, 'inj-ring', { border: '5px solid ' + PAL[7] });

    var syringe = document.createElement('img');
    syringe.className = 'inj-syringe';
    syringe.src = SYRINGE_SRC;
    syringe.alt = '';
    stage.appendChild(syringe);

    var flash = div(stage, 'inj-flash');

    var anims = [];
    var rate = opts.rate || 1;
    var loop = opts.loop !== false;
    var ephemeral = [];

    function seq(el, frames) {
      var END = loop ? CYCLE : OUTRO;
      var f = [];
      for (var i = 0; i < frames.length; i++) if (frames[i].t <= END) f.push(Object.assign({}, frames[i]));
      if (!f.length) return;

      if (f[0].t > 0) {
        // Maintien : l'élément reste strictement invisible jusqu'à sa première
        // image clé. Sans la seconde image, l'opacité monterait en fondu depuis
        // t=0 et l'on verrait les éclats attendre au centre avant l'impact.
        var pad = Object.assign({}, f[0], { easing: E.lin });
        if ('opacity' in f[0]) pad.opacity = 0;
        f.unshift(Object.assign({}, pad, { t: Math.max(0, f[0].t - 1) }));
        f.unshift(Object.assign({}, pad, { t: 0 }));
      }
      var last = f[f.length - 1];
      if (last.t < END) f.push(Object.assign({}, last, { t: END, easing: E.lin }));

      var kf = f.map(function (k) {
        var o = Object.assign({}, k);
        delete o.t;
        o.offset = Math.min(1, Math.max(0, k.t / END));
        return o;
      });

      var a = el.animate(kf, {
        duration: END,
        fill: 'both',
        easing: E.lin,
        iterations: loop ? Infinity : 1,
      });
      a.playbackRate = rate;
      anims.push(a);
    }

    /** Déplacement de la seringue le long de son axe (45°, aiguille en bas-gauche). */
    function sy(d, rot, sx, sy2) {
      return 'translate(' + d + 'px,' + -d + 'px) rotate(' + rot + 'deg) scale(' + sx + ',' + sy2 + ')';
    }

    function build() {
      anims.forEach(function (a) { a.cancel(); });
      anims = [];
      ephemeral.splice(0).forEach(function (el) { el.remove(); });
      var rnd = seeded(20250814);

      /* --- 1. seringue --- */
      seq(syringe, [
        { t: 0, transform: sy(640, -8, 1, 1), opacity: 0, filter: 'blur(9px)', easing: E.lin },
        { t: 60, transform: sy(520, -6, 1, 1), opacity: 1, filter: 'blur(7px)', easing: E.out },
        { t: 430, transform: sy(44, 2, 1, 1), opacity: 1, filter: 'blur(0px)', easing: E.outSoft },
        { t: 560, transform: sy(104, 4.5, 1, 1), easing: E.in },
        { t: 720, transform: sy(0, 0, 1, 1), easing: E.back },
        { t: 790, transform: sy(-6, -1.5, 1, 0.93), easing: E.outSoft },
        { t: 880, transform: sy(2, 0.5, 1, 0.97), opacity: 1, filter: 'blur(0px)', easing: E.out },
        { t: 1000, transform: sy(84, -2, 1, 1), opacity: 1, filter: 'blur(0px)', easing: E.in },
        { t: 1180, transform: sy(230, -5, 1, 1), opacity: 1, filter: 'blur(2px)', easing: E.in },
        { t: 1440, transform: sy(700, -10, 1, 1), opacity: 0, filter: 'blur(6px)', easing: E.lin },
        { t: 1441, transform: sy(640, -8, 1, 1), opacity: 0, filter: 'blur(9px)' },
      ]);

      /* --- 2. lignes de vitesse --- */
      for (var i = 0; i < 4; i++) {
        var off = -60 + i * 40;
        var el = div(stage, 'inj-streak', { width: 150 + i * 60 + 'px' });
        ephemeral.push(el);
        var P = (function (o) {
          return function (d) {
            return 'translate(' + (d + o) + 'px,' + (-d + o) + 'px) rotate(-45deg)';
          };
        })(off);
        seq(el, [
          { t: 30 + i * 30, opacity: 0, transform: P(360) + ' scaleX(.3)', easing: E.out },
          { t: 150 + i * 30, opacity: 0.8 },
          { t: 430 + i * 30, opacity: 0, transform: P(50) + ' scaleX(1)', easing: E.lin },
          { t: 431 + i * 30, opacity: 0 },
        ]);
      }

      /* --- 3. flashs d'impact --- */
      seq(flash, [
        { t: IMPACT - 20, opacity: 0, transform: 'scale(.3)', easing: E.burst },
        { t: IMPACT + 70, opacity: 1, transform: 'scale(1)', easing: E.outSoft },
        { t: IMPACT + 420, opacity: 0, transform: 'scale(1.9)', easing: E.lin },
        { t: IMPACT + 421, opacity: 0, transform: 'scale(.3)' },
      ]);
      seq(flashC, [
        { t: IMPACT - 10, opacity: 0, transform: 'scale(.25)', easing: E.burst },
        { t: IMPACT + 110, opacity: 0.9, transform: 'scale(1.05)', easing: E.outSoft },
        { t: IMPACT + 620, opacity: 0, transform: 'scale(1.7)', easing: E.lin },
        { t: IMPACT + 621, opacity: 0, transform: 'scale(.25)' },
      ]);

      /* --- 4. ondes de choc --- */
      [[0, 3.4, 660], [80, 4.2, 760], [170, 5.0, 880]].forEach(function (cfg, k) {
        seq(rings[k], [
          { t: IMPACT + cfg[0], opacity: 0.95, transform: 'scale(.18)', easing: E.burst },
          { t: IMPACT + cfg[0] + cfg[2], opacity: 0, transform: 'scale(' + cfg[1] + ')', easing: E.lin },
          { t: IMPACT + cfg[0] + cfg[2] + 1, opacity: 0, transform: 'scale(.18)' },
        ]);
      });

      /* --- 5. rayons --- */
      var NR = 16;
      for (var r = 0; r < NR; r++) {
        var ang = (r / NR) * 360 + rnd() * 6;
        var col = PAL[(rnd() * PAL.length) | 0];
        var ray = div(stage, 'inj-ray', {
          background: 'linear-gradient(90deg,' + col + ',rgba(255,255,255,0))',
        });
        ephemeral.push(ray);
        var R = (function (a) {
          return function (d, sx, sy2) {
            return 'rotate(' + a + 'deg) translateX(' + d + 'px) scale(' + sx + ',' + sy2 + ')';
          };
        })(ang);
        seq(ray, [
          { t: IMPACT - 10 + r * 4, opacity: 0, transform: R(10, 0.12, 1), easing: E.burst },
          { t: IMPACT + 60 + r * 4, opacity: 0.95, transform: R(60, 0.9, 1), easing: E.outSoft },
          { t: IMPACT + 460 + r * 4, opacity: 0, transform: R(240, 0.35, 0.3), easing: E.lin },
          { t: IMPACT + 461 + r * 4, opacity: 0, transform: R(10, 0.12, 1) },
        ]);
      }

      /* --- 6. gouttes --- */
      var ND = 24;
      for (var d2 = 0; d2 < ND; d2++) {
        var a2 = (d2 / ND) * Math.PI * 2 + (rnd() - 0.5) * 0.4;
        var dist = 150 + rnd() * 210;
        var sz = 8 + rnd() * 16;
        var drop = div(stage, 'inj-drop', {
          width: sz + 'px', height: sz + 'px',
          marginLeft: -sz / 2 + 'px', marginTop: -sz / 2 + 'px',
          background: PAL[(rnd() * PAL.length) | 0],
        });
        ephemeral.push(drop);
        var dur = 620 + rnd() * 420;
        var dl = rnd() * 90;
        seq(drop, [
          { t: IMPACT + dl, opacity: 1, transform: 'translate(0,0) scale(.15)', easing: E.burst },
          { t: IMPACT + dl + dur * 0.28, opacity: 1,
            transform: 'translate(' + Math.cos(a2) * dist * 0.6 + 'px,' + Math.sin(a2) * dist * 0.6 + 'px) scale(1.1)',
            easing: E.outSoft },
          { t: IMPACT + dl + dur, opacity: 0,
            transform: 'translate(' + Math.cos(a2) * dist + 'px,' + (Math.sin(a2) * dist + 60) + 'px) scale(.12)',
            easing: E.lin },
          { t: IMPACT + dl + dur + 1, opacity: 0, transform: 'translate(0,0) scale(.15)' },
        ]);
      }

      /* --- 7. étincelles --- */
      for (var s2 = 0; s2 < 12; s2++) {
        var as = rnd() * 360;
        var spark = div(stage, 'inj-spark', {
          width: 26 + rnd() * 40 + 'px',
          background: PAL[(rnd() * PAL.length) | 0],
        });
        ephemeral.push(spark);
        var ds = 170 + rnd() * 190;
        var RS = (function (a) {
          return function (dd) { return 'rotate(' + a + 'deg) translateX(' + dd + 'px)'; };
        })(as);
        seq(spark, [
          { t: IMPACT + 10, opacity: 0, transform: RS(30) + ' scaleX(.2)', easing: E.burst },
          { t: IMPACT + 90, opacity: 0.9, transform: RS(120) + ' scaleX(1)', easing: E.lin },
          { t: IMPACT + 520, opacity: 0, transform: RS(ds) + ' scaleX(.2)', easing: E.lin },
          { t: IMPACT + 521, opacity: 0, transform: RS(30) + ' scaleX(.2)' },
        ]);
      }

      /* --- 8. secousse d'écran --- */
      seq(stage, [
        { t: IMPACT - 5, transform: 'translate(0,0)', easing: E.out },
        { t: IMPACT + 30, transform: 'translate(9px,-7px)', easing: E.out },
        { t: IMPACT + 75, transform: 'translate(-8px,6px)', easing: E.out },
        { t: IMPACT + 120, transform: 'translate(5px,4px)', easing: E.out },
        { t: IMPACT + 165, transform: 'translate(-3px,-2px)', easing: E.out },
        { t: IMPACT + 215, transform: 'translate(0,0)', easing: E.lin },
      ]);

      /* --- 9. révélation de la marque --- */
      seq(logoWrap, [
        { t: IMPACT + 10, opacity: 0, clipPath: 'circle(0% at 50% 52.8%)', easing: E.out },
        { t: IMPACT + 60, opacity: 1, easing: E.out },
        { t: IMPACT + 330, opacity: 1, clipPath: 'circle(80% at 50% 52.8%)', easing: E.lin },
        { t: OUTRO + 400, opacity: 1, clipPath: 'circle(80% at 50% 52.8%)', easing: E.lin },
        { t: OUTRO + 420, opacity: 0, clipPath: 'circle(80% at 50% 52.8%)' },
      ]);
      seq(logoInner, [
        { t: IMPACT + 10, transform: 'scale(.12,.12) rotate(-14deg)', easing: E.out },
        { t: IMPACT + 130, transform: 'scale(1.3,.72) rotate(4deg)', easing: E.outSoft },
        { t: IMPACT + 260, transform: 'scale(.88,1.14) rotate(-3deg)', easing: E.outSoft },
        { t: IMPACT + 400, transform: 'scale(1.06,.96) rotate(1.2deg)', easing: E.outSoft },
        { t: IMPACT + 560, transform: 'scale(.99,1.01) rotate(-.4deg)', easing: E.outSoft },
        { t: IMPACT + 700, transform: 'scale(1,1) rotate(0deg)', easing: E.outSoft },
        { t: 1900, transform: 'scale(1.015,1.015) rotate(0deg)', easing: E.outSoft },
        { t: OUTRO, transform: 'scale(1,1) rotate(0deg)', easing: E.outSoft },
        { t: OUTRO + 110, transform: 'scale(1.14,.86) rotate(0deg)', easing: E.in },
        { t: OUTRO + 400, transform: 'scale(.02,.02) rotate(14deg)', easing: E.lin },
        { t: OUTRO + 401, transform: 'scale(.12,.12) rotate(-14deg)' },
      ]);

      /* --- 10. le produit diffuse --- */
      seq(fluid, [
        { t: IMPACT + 40, opacity: 0, transform: 'scale(.05)', easing: E.out },
        { t: IMPACT + 120, opacity: 1, transform: 'scale(.38)', easing: E.outSoft },
        { t: IMPACT + 420, opacity: 0.92, transform: 'scale(1.02)', easing: E.outSoft },
        { t: IMPACT + 780, opacity: 0.45, transform: 'scale(1.3)', easing: E.outSoft },
        { t: IMPACT + 1180, opacity: 0, transform: 'scale(1.6)', easing: E.lin },
        { t: IMPACT + 1181, opacity: 0, transform: 'scale(.05)' },
      ]);

      /* --- 11. halo --- */
      seq(halo, [
        { t: IMPACT + 20, opacity: 0, transform: 'scale(.3)', easing: E.burst },
        { t: IMPACT + 180, opacity: 0.85, transform: 'scale(1)', easing: E.outSoft },
        { t: 1500, opacity: 0.32, transform: 'scale(.92)', easing: E.outSoft },
        { t: 2100, opacity: 0.5, transform: 'scale(1.02)', easing: E.outSoft },
        { t: OUTRO + 260, opacity: 0, transform: 'scale(.4)', easing: E.in },
        { t: OUTRO + 261, opacity: 0, transform: 'scale(.3)' },
      ]);

      /* --- 12. reflet --- */
      seq(shine, [
        { t: 1480, opacity: 0, transform: 'translateX(-200%) rotate(18deg)', easing: E.outSoft },
        { t: 1620, opacity: 0.6, easing: E.lin },
        { t: 2020, opacity: 0.6, easing: E.outSoft },
        { t: 2160, opacity: 0, transform: 'translateX(420%) rotate(18deg)', easing: E.lin },
        { t: 2161, opacity: 0, transform: 'translateX(-200%) rotate(18deg)' },
      ]);

      /* --- 13. onde qui se referme à la sortie --- */
      seq(ringIn, [
        { t: OUTRO + 60, opacity: 0, transform: 'scale(3.6)', easing: E.in },
        { t: OUTRO + 140, opacity: 0.9, easing: E.in },
        { t: OUTRO + 400, opacity: 0, transform: 'scale(.1)', easing: E.lin },
        { t: OUTRO + 401, opacity: 0, transform: 'scale(3.6)' },
      ]);

      anims.forEach(function (a) { a.play(); });
    }

    var api = {
      /** (Re)lance le cycle depuis le début. */
      play: function () {
        build();
        return api;
      },
      /** Arrête tout et vide la scène — plus rien ne tourne, plus rien ne s'affiche. */
      stop: function () {
        anims.forEach(function (a) { a.cancel(); });
        anims = [];
        ephemeral.splice(0).forEach(function (el) { el.remove(); });
        return api;
      },
      setRate: function (value) {
        rate = value;
        anims.forEach(function (a) { a.playbackRate = value; });
        return api;
      },
      setLoop: function (value) {
        loop = value;
        return api;
      },
      isLooping: function () { return loop; },
      /** Taille affichée, en px. La scène reste calculée en unités de 720. */
      setSize: function (px) {
        fit.style.width = px + 'px';
        fit.style.height = px + 'px';
        scale.style.transform = 'scale(' + px / BASE + ')';
        return api;
      },
      /** Résout quand les deux illustrations sont décodées. */
      ready: function () {
        return Promise.all([logoImg, syringe].map(function (img) {
          return img.decode ? img.decode().catch(function () {}) : Promise.resolve();
        }));
      },
      destroy: function () {
        api.stop();
        fit.remove();
      },
      element: fit,
    };

    api.setSize(opts.size || BASE);
    return api;
  }

  global.InjectionAnim = { create: create, CYCLE: CYCLE };
})(window);
