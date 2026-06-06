interface LoadingIndicatorProps {
  label: string;
  compact?: boolean;
}

export default function LoadingIndicator({ label, compact = false }: LoadingIndicatorProps) {
  return (
    <div className={compact ? 'loading-indicator loading-indicator-compact' : 'loading-indicator'}>
      <span aria-hidden="true" className="spinner" />
      <span>{label}</span>
    </div>
  );
}
