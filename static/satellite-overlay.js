// Independent 2D Map Layer: Satellite Tracking Overlay (V1)
// Respects the active PlanetMapCanvas projection, zoom, pan, and antimeridian-split segments.

export class SatelliteMapOverlay {
  constructor() {
    this.enabled = true;
    this.showTrajectory = true;
    this.satellites = [];
    this.hoveredNoradId = null;
    this.selectedNoradId = null;
  }

  updateData(payload) {
    if (!payload) return;
    if (payload.config) {
      this.enabled = payload.config.enabled !== false;
      this.showTrajectory = payload.config.showTrajectory !== false;
    }
    if (Array.isArray(payload.satellites)) {
      this.satellites = payload.satellites;
    }
  }

  activeSatellites() {
    if (!this.enabled) return [];
    return this.satellites.filter((s) => s.enabled && s.position && s.position.valid);
  }

  hitTest(mx, my) {
    if (!this.enabled) return null;
    let best = null;
    let bestDist = 20;
    for (const sat of this.satellites) {
      if (!sat.enabled || !sat.position || !sat.position.valid || sat._sx === undefined) continue;
      const d = Math.hypot(mx - sat._sx, my - sat._sy);
      if (d < bestDist) {
        bestDist = d;
        best = sat;
      }
    }
    return best;
  }

  drawSegmentedPolyline(ctx, mapCanvas, segments) {
    if (!Array.isArray(segments)) return;
    for (const seg of segments) {
      if (!Array.isArray(seg) || seg.length < 2) continue;
      ctx.beginPath();
      let prevSx = null;
      for (let i = 0; i < seg.length; i++) {
        const [lon, lat] = seg[i];
        const [sx, sy] = mapCanvas.projectToScreen(lon, lat);
        // Defensive guard against any abrupt jump across the projection width
        if (i === 0 || (prevSx !== null && Math.abs(sx - prevSx) > mapCanvas.viewW * 0.45 && Math.abs(lon) < 179.5)) {
          ctx.moveTo(sx, sy);
        } else {
          ctx.lineTo(sx, sy);
        }
        prevSx = sx;
      }
      ctx.stroke();
    }
  }

  drawSatelliteGlyph(ctx, sx, sy, color, isHot) {
    ctx.save();
    ctx.translate(sx, sy);

    // Solar panel wings
    ctx.strokeStyle = isHot ? '#ffffff' : color;
    ctx.lineWidth = isHot ? 2.2 : 1.7;
    ctx.fillStyle = isHot ? 'rgba(255,255,255,0.28)' : 'rgba(15, 23, 42, 0.9)';

    // Left and right wing panels
    ctx.fillRect(-10, -3.2, 5.5, 6.4);
    ctx.strokeRect(-10, -3.2, 5.5, 6.4);
    ctx.fillRect(4.5, -3.2, 5.5, 6.4);
    ctx.strokeRect(4.5, -3.2, 5.5, 6.4);

    // Truss crossbar
    ctx.beginPath();
    ctx.moveTo(-4.5, 0);
    ctx.lineTo(4.5, 0);
    ctx.stroke();

    // Central core module
    ctx.beginPath();
    ctx.arc(0, 0, isHot ? 4.2 : 3.4, 0, Math.PI * 2);
    ctx.fillStyle = isHot ? '#ffffff' : color;
    ctx.fill();
    ctx.lineWidth = 1.4;
    ctx.strokeStyle = '#030712';
    ctx.stroke();

    ctx.restore();
  }

  render(ctx, mapCanvas, timeSec) {
    for (const sat of this.satellites) {
      sat._sx = undefined;
      sat._sy = undefined;
    }
    if (!this.enabled || !this.satellites.length) return;

    for (const sat of this.satellites) {
      if (!sat.enabled || !sat.position || !sat.position.valid) continue;

      const color = sat.color || '#22d3ee';
      const isHot = this.hoveredNoradId === sat.noradId || this.selectedNoradId === sat.noradId;

      // 1. Orbital ground tracks (past solid trail + future dashed projection)
      if (this.showTrajectory && sat.track) {
        if (Array.isArray(sat.track.past) && sat.track.past.length > 0) {
          ctx.save();
          ctx.strokeStyle = color;
          ctx.lineWidth = isHot ? 2.2 : 1.5;
          ctx.globalAlpha = isHot ? 0.65 : 0.38;
          ctx.setLineDash([]);
          this.drawSegmentedPolyline(ctx, mapCanvas, sat.track.past);
          ctx.restore();
        }

        if (Array.isArray(sat.track.future) && sat.track.future.length > 0) {
          ctx.save();
          ctx.strokeStyle = color;
          ctx.lineWidth = isHot ? 2.4 : 1.7;
          ctx.globalAlpha = isHot ? 0.95 : 0.72;
          ctx.setLineDash([6, 5]);
          if (mapCanvas.showAnimations) {
            ctx.lineDashOffset = -timeSec * 16;
          }
          if (isHot) {
            ctx.shadowColor = color;
            ctx.shadowBlur = 8;
          }
          this.drawSegmentedPolyline(ctx, mapCanvas, sat.track.future);
          ctx.restore();
        }
      }

      // 2. Satellite position marker
      const [sx, sy] = mapCanvas.projectToScreen(sat.position.lon, sat.position.lat);
      sat._sx = sx;
      sat._sy = sy;

      ctx.save();

      // Animated orbital beacon ring
      if (mapCanvas.showAnimations || isHot) {
        const pulse = (timeSec * 0.75 + (sat.noradId % 7) * 0.13) % 1;
        ctx.beginPath();
        ctx.arc(sx, sy, 8 + pulse * 14, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.globalAlpha = (1 - pulse) * (isHot ? 0.8 : 0.45);
        ctx.lineWidth = isHot ? 1.8 : 1.2;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      // Soft ambient halo
      ctx.beginPath();
      ctx.arc(sx, sy, isHot ? 14 : 11, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.globalAlpha = isHot ? 0.28 : 0.14;
      ctx.fill();
      ctx.globalAlpha = 1;

      // Satellite station glyph
      this.drawSatelliteGlyph(ctx, sx, sy, color, isHot);

      // Visual identification & name label
      if (mapCanvas.showLabels || isHot) {
        const altStr = Number.isFinite(sat.position.altitudeKm)
          ? `${Math.round(sat.position.altitudeKm)} km`
          : '';
        const label = altStr ? `${sat.shortName || sat.code} · ${altStr}` : (sat.shortName || sat.code);

        ctx.font = '600 10.5px "JetBrains Mono", Consolas, monospace';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        const tw = ctx.measureText(label).width + 12;
        const lx = sx + 13;
        const ly = sy - 9;

        ctx.fillStyle = 'rgba(2, 6, 23, 0.86)';
        ctx.fillRect(lx, ly, tw, 18);
        ctx.strokeStyle = isHot ? '#ffffff' : color;
        ctx.globalAlpha = isHot ? 0.95 : 0.6;
        ctx.lineWidth = 1;
        ctx.strokeRect(lx, ly, tw, 18);
        ctx.globalAlpha = 1;
        ctx.fillStyle = '#f8fafc';
        ctx.fillText(label, lx + 6, sy);
      }

      ctx.restore();
    }
  }
}
