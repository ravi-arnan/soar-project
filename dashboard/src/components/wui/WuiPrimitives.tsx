'use client';

import React, { useState } from 'react';
import { WuiIcon, type WuiIconType } from './WuiIcon';

/**
 * Komponen primitif UI berstandar Wazuh Dashboard / OpenSearch UI (OUI):
 * flat 1px borders (#D3DAE6), radius 4px, warna resmi _colors.scss, ikon resmi OuiIcon.
 */

export type WuiTone = 'default' | 'primary' | 'success' | 'warning' | 'danger';

const BADGE_STYLES: Record<WuiTone, string> = {
  default: 'bg-[#F5F7FA] text-[#343741] border-[#D3DAE6]',
  primary: 'bg-[#EBF5FB] text-[#006BB4] border-[#C5E0F5]',
  success: 'bg-[#E6F4F3] text-[#017D73] border-[#BBDEDB]',
  warning: 'bg-[#FFF8E5] text-[#935E00] border-[#F6DF98]',
  danger: 'bg-[#FBECEB] text-[#BD271E] border-[#F3C5C3]',
};

const HEALTH_ICON: Record<WuiTone, { icon: WuiIconType; text: string }> = {
  default: { icon: 'iInCircle', text: 'text-[#69707D]' },
  primary: { icon: 'iInCircle', text: 'text-[#006BB4]' },
  success: { icon: 'checkInCircleFilled', text: 'text-[#017D73]' },
  warning: { icon: 'alert', text: 'text-[#935E00]' },
  danger: { icon: 'crossInCircleFilled', text: 'text-[#BD271E]' },
};

export function WuiBadge({
  children,
  tone = 'default',
  className = '',
}: {
  children: React.ReactNode;
  tone?: WuiTone;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-[4px] border text-[11px] font-medium leading-tight ${BADGE_STYLES[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

/** Indikator status khas OUI (OuiHealth): ikon status 12px + teks semantik tanpa bulatan dekoratif. */
export function WuiHealth({
  tone = 'default',
  children,
  className = '',
}: {
  tone?: WuiTone;
  children: React.ReactNode;
  className?: string;
}) {
  const cfg = HEALTH_ICON[tone];
  return (
    <span className={`inline-flex items-center gap-1.5 text-[12px] font-medium ${cfg.text} ${className}`}>
      <WuiIcon type={cfg.icon} size="s" />
      <span className="text-[#1A1C21]">{children}</span>
    </span>
  );
}

export function WuiPanel({
  title,
  subtitle,
  right,
  children,
  className = '',
  bodyClassName = 'p-4',
}: {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  right?: React.ReactNode;
  accentColor?: string;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section
      className={`bg-white border border-[#D3DAE6] rounded-[4px] overflow-hidden ${className}`}
    >
      {(title || right) && (
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-[#E9EDF3]">
          <div className="min-w-0">
            {typeof title === 'string' ? (
              <h2 className="text-[14px] font-semibold text-[#1A1C21] leading-snug truncate">
                {title}
              </h2>
            ) : (
              title
            )}
            {subtitle && (
              <p className="text-[12px] text-[#535966] mt-0.5">{subtitle}</p>
            )}
          </div>
          {right && <div className="flex items-center gap-2 shrink-0">{right}</div>}
        </div>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

export function WuiPageHeader({
  title,
  description,
  actions,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="bg-white border border-[#D3DAE6] rounded-[4px] px-4 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-[18px] font-semibold text-[#1A1C21] leading-snug flex items-center gap-2">
          {title}
        </h1>
        {description && (
          <p className="text-[12px] text-[#535966] mt-0.5 max-w-3xl leading-relaxed">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

const CALLOUT_STYLES: Record<
  Exclude<WuiTone, 'default'>,
  { wrap: string; iconColor: string; icon: WuiIconType }
> = {
  primary: {
    wrap: 'bg-[#F4F9FD] border-[#C5E0F5] border-l-[#006BB4] text-[#1A1C21]',
    iconColor: 'text-[#006BB4]',
    icon: 'iInCircle',
  },
  success: {
    wrap: 'bg-[#F1FAF9] border-[#BBDEDB] border-l-[#017D73] text-[#1A1C21]',
    iconColor: 'text-[#017D73]',
    icon: 'checkInCircleFilled',
  },
  warning: {
    wrap: 'bg-[#FFFDF5] border-[#F6DF98] border-l-[#F5A700] text-[#1A1C21]',
    iconColor: 'text-[#935E00]',
    icon: 'alert',
  },
  danger: {
    wrap: 'bg-[#FDF5F5] border-[#F3C5C3] border-l-[#BD271E] text-[#1A1C21]',
    iconColor: 'text-[#BD271E]',
    icon: 'crossInCircleFilled',
  },
};

export function WuiCallOut({
  tone = 'primary',
  title,
  children,
  className = '',
}: {
  tone?: Exclude<WuiTone, 'default'>;
  title?: string;
  children: React.ReactNode;
  className?: string;
}) {
  const cfg = CALLOUT_STYLES[tone];
  return (
    <div
      className={`border border-l-[3px] rounded-[4px] px-3.5 py-2.5 text-[12px] flex items-start gap-2.5 ${cfg.wrap} ${className}`}
    >
      <WuiIcon type={cfg.icon} size="m" className={`mt-0.5 ${cfg.iconColor}`} />
      <div className="min-w-0 flex-1">
        {title && <div className="font-semibold text-[#1A1C21] mb-0.5">{title}</div>}
        <div className="text-[#343741] leading-relaxed">{children}</div>
      </div>
    </div>
  );
}

export function WuiCodeBlock({
  code,
  label,
  helperText,
  multiline = false,
}: {
  code: string;
  label?: string;
  helperText?: string;
  multiline?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (!navigator?.clipboard) return;
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="space-y-1.5">
      {label && <div className="text-[12px] font-medium text-[#1A1C21]">{label}</div>}
      <div
        className={`bg-[#F5F7FA] border border-[#D3DAE6] rounded-[4px] px-3.5 py-2.5 flex justify-between gap-3 ${
          multiline ? 'items-start' : 'items-center'
        }`}
      >
        <code
          className={`font-mono text-[12px] text-[#1A1C21] select-all leading-relaxed ${
            multiline ? 'whitespace-pre-wrap break-words' : 'break-all'
          }`}
        >
          {code}
        </code>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 px-2 py-1 rounded-[4px] bg-white border border-[#D3DAE6] text-[11px] font-medium text-[#343741] hover:border-[#006BB4] hover:text-[#006BB4] transition-colors shrink-0 cursor-pointer"
          title="Salin"
        >
          {copied ? (
            <>
              <WuiIcon type="check" size="s" className="text-[#017D73]" />
              <span className="text-[#017D73]">Tersalin</span>
            </>
          ) : (
            <>
              <WuiIcon type="copy" size="s" />
              <span>Salin</span>
            </>
          )}
        </button>
      </div>
      {helperText && <div className="text-[11px] text-[#535966]">{helperText}</div>}
    </div>
  );
}

export function WuiModal({
  title,
  onClose,
  children,
  footer,
  maxWidth = 'max-w-md',
}: {
  title: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  maxWidth?: string;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#1A1C21]/40 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div
        className={`bg-white border border-[#D3DAE6] rounded-[4px] shadow-[0_6px_24px_rgba(0,0,0,0.14)] w-full ${maxWidth} overflow-hidden`}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#D3DAE6]">
          <h3 className="text-[14px] font-semibold text-[#1A1C21] flex items-center gap-2">
            {title}
          </h3>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-[4px] text-[#69707D] hover:bg-[#F5F7FA] hover:text-[#1A1C21] transition-colors cursor-pointer"
            aria-label="Tutup"
          >
            <WuiIcon type="cross" size="m" />
          </button>
        </div>
        <div className="p-4">{children}</div>
        {footer && (
          <div className="px-4 py-3 border-t border-[#E9EDF3] flex items-center justify-end gap-2">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
