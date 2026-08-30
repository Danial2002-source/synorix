import React from 'react';
import { Clock, Sparkles, AlertCircle } from 'lucide-react';
import './PhaseNotice.css';

interface PhaseNoticeProps {
  phase?: string;
  title: string;
  description: string;
  isMockData?: boolean;
  statusBadge?: string;
}

export const PhaseNotice: React.FC<PhaseNoticeProps> = ({
  phase = "Phase 2 in Progress (Oct – Dec 2026)",
  title,
  description,
  isMockData = true,
  statusBadge = "45% FYP-1 Milestone Completed"
}) => {
  return (
    <div className="phase-notice-banner">
      <div className="phase-notice-tags">
        <span className="phase-badge-milestone">
          <Clock size={13} style={{ marginRight: '5px' }} />
          {statusBadge}
        </span>
        <span className="phase-badge-upcoming">
          <Sparkles size={13} style={{ marginRight: '5px' }} />
          {phase}
        </span>
        {isMockData && (
          <span className="phase-badge-simulation">
            <AlertCircle size={13} style={{ marginRight: '5px' }} />
            Prototype Simulation Mode
          </span>
        )}
      </div>
      <div className="phase-notice-content">
        <h4 className="phase-notice-heading">{title}</h4>
        <p className="phase-notice-text">{description}</p>
      </div>
    </div>
  );
};

export default PhaseNotice;
