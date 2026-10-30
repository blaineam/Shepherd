// Constants shared by the 3D globe and the 2D map, kept out of globe.js so the
// 2D map never has to load the WebGL library.
export const LANE_CAP = 300;
export const COMET_CAP = 600;
export const PULSE_CAP = 192;

export const COLORS = {
  allowed: [0.086, 0.78, 0.741],
  cached: [0.416, 0.651, 0.949],
  blocked: [0.949, 0.439, 0.42],
  error: [0.941, 0.714, 0.29],
};
