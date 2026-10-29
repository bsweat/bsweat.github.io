(function () {
  const landing = document.querySelector('.landing');
  const canvas = document.getElementById('cursor-canvas');
  const orb = document.getElementById('cursor-orb');
  const toggle = document.getElementById('cursor-toggle');
  const info = document.getElementById('landing-info');
  if (!landing || !canvas || !orb || !toggle) return;

  document.body.classList.add('page-loaded');
  document.querySelectorAll('a[href]').forEach((link) => {
    const href = link.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('http') || link.target === '_blank') return;
    link.addEventListener('click', (event) => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      document.body.classList.add('page-leaving');
      setTimeout(() => { window.location.href = href; }, 85);
    });
  });
  const ctx = canvas.getContext('2d');
  const palette = ['#00A3E0', '#8E44AD', '#E53935', '#FB8C00', '#FBC02D', '#4CAF50'];
  const washColors = palette.map(color => color + '88');
  const pixelColors = palette;
  const matrixColors = palette;
  const modes = ['ink', 'orb', 'pixel', 'matrix'];
  const touchInput = matchMedia('(pointer: coarse)').matches;
  const inputLabel = touchInput ? 'touch: ' : 'cursor: ';
  let mode = 'pixel';
  landing.dataset.cursorMode = mode;
  toggle.textContent = inputLabel + mode;
  let points = [];
  let ripples = [];

  function resize() {
    const dpr = Math.min(devicePixelRatio || 1, 2);
    canvas.width = Math.floor(innerWidth * dpr);
    canvas.height = Math.floor(innerHeight * dpr);
    canvas.style.width = innerWidth + 'px';
    canvas.style.height = innerHeight + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.imageSmoothingEnabled = false;
  }

  function drawMatrixBit(p) {
    p.y += p.fall;
    p.x += p.drift;
    p.phase += .14;
    const glyph = Math.sin(p.phase) > 0 ? '1' : '0';
    ctx.globalAlpha = p.life;
    ctx.fillStyle = p.color;
    ctx.font = '760 ' + p.size + 'px SFMono-Regular, Menlo, monospace';
    ctx.fillText(glyph, p.x, p.y);
    ctx.globalAlpha = p.life * .26;
    ctx.fillText(glyph, p.x, p.y - p.size * 1.2);
  }

  function drawPixel(p) {
    const unit = p.unit;
    const x = Math.round(p.x / unit) * unit;
    const y = Math.round(p.y / unit) * unit;
    ctx.globalAlpha = p.life;
    ctx.fillStyle = p.color;
    ctx.fillRect(x, y, unit, unit);
    if (p.life > .35) {
      ctx.fillStyle = 'rgba(255,253,248,.45)';
      ctx.fillRect(x + unit, y, unit, unit);
    }
  }

  function drawWash(p) {
    const gradient = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.radius);
    gradient.addColorStop(0, p.color);
    gradient.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.globalAlpha = p.life;
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
    ctx.fill();
  }

  function drawRipples() {
    ripples = ripples.filter(r => r.life > 0.01);
    for (const r of ripples) {
      r.life *= .986;
      r.radius += 1.55;
      if (r.binary) {
        const steps = Math.max(18, Math.floor(r.radius / 5));
        ctx.globalAlpha = Math.min(r.life, .86);
        ctx.fillStyle = r.color;
        ctx.font = '760 16px SFMono-Regular, Menlo, monospace';
        for (let i = 0; i < steps; i++) {
          const angle = (Math.PI * 2 * i) / steps;
          const x = r.x + Math.cos(angle) * r.radius;
          const y = r.y + Math.sin(angle) * r.radius;
          ctx.fillText(i % 2 ? '1' : '0', x, y);
        }
      } else if (r.pixelated) {
        const unit = 10;
        ctx.fillStyle = r.color;
        // Four perpendicular rays share one rotation for the entire burst.
        // A short moving tail makes each arm radiate away from the click.
        for (let arm = 0; arm < 4; arm++) {
          const angle = r.rotation + arm * Math.PI / 2;
          for (let trail = 0; trail < 9; trail++) {
            const distance = r.radius - trail * unit * 1.2;
            if (distance < 0) continue;
            ctx.globalAlpha = Math.min(r.life, .9) * (1 - trail / 9);
            const x = r.x + Math.round(Math.cos(angle) * distance / unit) * unit;
            const y = r.y + Math.round(Math.sin(angle) * distance / unit) * unit;
            ctx.fillRect(x - unit / 2, y - unit / 2, unit, unit);
          }
        }
      } else {
        ctx.globalAlpha = Math.min(r.life, .72);
        ctx.strokeStyle = r.color;
        ctx.lineWidth = 3;
        ctx.beginPath();
        ctx.arc(r.x, r.y, r.radius, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = r.life * .12;
        ctx.fillStyle = r.color;
        ctx.beginPath();
        ctx.arc(r.x, r.y, r.radius * .55, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    ctx.globalAlpha = 1;
  }

  function draw() {
    ctx.clearRect(0, 0, innerWidth, innerHeight);
    points = points.filter(p => p.life > 0.01 && p.y < innerHeight + 80);
    for (const p of points) {
      if (p.kind === 'matrix') {
        p.life *= .977;
        drawMatrixBit(p);
      } else if (p.kind === 'pixel') {
        p.life *= .962;
        drawPixel(p);
      } else {
        p.life *= .965;
        p.radius += mode === 'ink' ? 1.35 : .7;
        drawWash(p);
      }
    }
    drawRipples();
    ctx.globalAlpha = 1;
    requestAnimationFrame(draw);
  }

  function addPoint(x, y) {
    if (mode === 'matrix') {
      points.push({
        kind: 'matrix',
        x: x + (Math.random() - .5) * 28,
        y: y + (Math.random() - .5) * 16,
        fall: .85 + Math.random() * 2.1,
        drift: (Math.random() - .5) * .9,
        size: 14 + Math.random() * 18,
        phase: Math.random() * 10,
        life: 1,
        color: matrixColors[Math.floor(Math.random() * matrixColors.length)],
      });
    } else if (mode === 'pixel') {
      const unit = 8 + Math.floor(Math.random() * 3) * 4;
      points.push({
        kind: 'pixel',
        x: x + (Math.random() - .5) * 22,
        y: y + (Math.random() - .5) * 22,
        unit,
        life: 1,
        color: pixelColors[Math.floor(Math.random() * pixelColors.length)],
      });
    } else {
      points.push({
        kind: 'wash',
        x,
        y,
        radius: mode === 'ink' ? 12 + Math.random() * 18 : 5 + Math.random() * 9,
        life: 1,
        color: washColors[Math.floor(Math.random() * washColors.length)],
      });
    }
    if (points.length > 170) points.splice(0, points.length - 170);
  }

  function move(event) {
    orb.style.transform = 'translate3d(' + event.clientX + 'px,' + event.clientY + 'px,0) translate(-50%, -50%)';
    addPoint(event.clientX, event.clientY);
    if (mode === 'pixel' || mode === 'matrix') addPoint(event.clientX, event.clientY);
  }

  function setMode(next) {
    mode = next;
    landing.dataset.cursorMode = mode;
    toggle.textContent = inputLabel + mode;
    points = [];
  }

  toggle.addEventListener('click', () => setMode(modes[(modes.indexOf(mode) + 1) % modes.length]));
  function burst(event) {
    move(event);
    ripples.push({
      x: event.clientX,
      y: event.clientY,
      radius: 8,
      rotation: Math.random() * Math.PI / 2,
      life: 1,
      color: palette[Math.floor(Math.random() * palette.length)],
      pixelated: mode === 'pixel',
      binary: mode === 'matrix',
    });
    if (ripples.length > 24) ripples.splice(0, ripples.length - 24);
    if (mode !== 'pixel') {
      for (let i = 0; i < 10; i++) addPoint(event.clientX + (Math.random() - .5) * 42, event.clientY + (Math.random() - .5) * 42);
    }
  }
  // Pointer events cover current mobile browsers; touch events support older ones.
  if ('PointerEvent' in window) {
    landing.addEventListener('pointermove', move, { passive: true });
    landing.addEventListener('pointerdown', burst, { passive: true });
  } else {
    landing.addEventListener('touchstart', event => {
      for (const touch of event.changedTouches) burst(touch);
    }, { passive: true });
    landing.addEventListener('touchmove', event => {
      for (const touch of event.changedTouches) move(touch);
    }, { passive: true });
    landing.addEventListener('mousemove', move, { passive: true });
    landing.addEventListener('mousedown', burst, { passive: true });
  }
  if (info) {
    info.addEventListener('click', () => {
      info.classList.remove('shine');
      void info.offsetWidth;
      info.classList.add('shine');
    });
  }
  addEventListener('resize', resize);
  resize();
  draw();

})();










