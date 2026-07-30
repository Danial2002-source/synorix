/**
 * Synorix Design System — Central Theme Constants
 * SaaS Light Design Language
 * Updated: 2026-03-15
 */

// ─── Base Backgrounds ─────────────────────────────────────────────────────────
export const COLORS = {
  // Backgrounds
  bgApp:        '#F5F7F6',
  bgSurface:    '#FFFFFF',
  bgSidebar:    '#EEF2EF',
  bgPanel:      '#F7F8F7',
  bgInput:      '#FFFFFF',
  bgNeutralBar: '#EAECE8',

  // Text
  textPrimary:     '#1F2933',
  textSecondary:   '#6B7280',
  textMuted:       '#9CA3AF',
  textPlaceholder: '#B6BDC6',

  // Borders
  borderMain:   '#E5E7EB',
  borderSoft:   '#ECEFEC',

  // Brand / Accent Greens
  greenLight:   '#B6E17D',
  greenHover:   '#A8D96A',
  greenDark:    '#145C4C',
  greenDarker:  '#0F4D40',
  greenEmerald: '#22C55E',
  greenTeal:    '#2D7D6E',
  mintGlow:     '#DFF3E4',

  // Status
  red:          '#EF4444',
  redBg:        '#FEE2E2',
  yellow:       '#FDE68A',
  purple:       '#E3F2FD',
  orange:       '#FF7A59',

  // Chart Colors
  chartPrimary:   '#145C4C',
  chartSecondary: '#7FBF6A',
  chartBar1:      '#EAECE8',
  chartBar2:      '#FF7A59',
  chartBar3:      '#B6E17D',

  // Donut/Pie
  donut1: '#145C4C',
  donut2: '#B6E17D',
  donut3: '#FF7A59',
  donut4: '#E3F2FD',
  donut5: '#FDE68A',
  donut6: '#D1D5DB',

  // Badge: Success
  badgeSuccessBg:   '#DCFCE7',
  badgeSuccessText: '#16A34A',
  // Badge: Warning
  badgeWarnBg:   '#FEF3C7',
  badgeWarnText: '#D97706',
  // Badge: Danger
  badgeDangerBg:   '#FEE2E2',
  badgeDangerText: '#DC2626',
  // Badge: Info
  badgeInfoBg:   '#E0F2FE',
  badgeInfoText: '#0284C7',
  // Badge: Muted
  badgeMutedBg:   '#F3F4F6',
  badgeMutedText: '#6B7280',
} as const;

// ─── Shadows ──────────────────────────────────────────────────────────────────
export const SHADOWS = {
  card:    '0 8px 20px rgba(16, 24, 40, 0.05)',
  cardLg:  '0 10px 30px rgba(16, 24, 40, 0.06)',
  tooltip: '0 10px 25px rgba(16, 24, 40, 0.08)',
} as const;

// ─── Border Radius ────────────────────────────────────────────────────────────
export const RADII = {
  sm:    '8px',
  md:    '10px',
  card:  '16px',
  cardLg:'18px',
  full:  '999px',
} as const;

// ─── Spacing ──────────────────────────────────────────────────────────────────
export const SPACING = {
  pagePadding: '24px',
  gridGap:     '24px',
  cardPadding: '20px',
  sectionGap:  '24px',
} as const;

// ─── Typography ───────────────────────────────────────────────────────────────
export const TYPOGRAPHY = {
  fontFamily: "'Inter', ui-sans-serif, system-ui, sans-serif",
  heading:    { size: '32px', weight: '700', lineHeight: '1.2' },
  sectionTitle:{ size: '22px', weight: '600' },
  kpiValue:   { size: '30px', weight: '700' },
  kpiLabel:   { size: '13px', weight: '500' },
  tableHeader:{ size: '14px', weight: '600' },
  meta:       { size: '12px', weight: '500' },
} as const;

// ─── Layout ───────────────────────────────────────────────────────────────────
export const LAYOUT = {
  sidebarWidth: '248px',
  navbarHeight: '68px',
} as const;

export default { COLORS, SHADOWS, RADII, SPACING, TYPOGRAPHY, LAYOUT };
