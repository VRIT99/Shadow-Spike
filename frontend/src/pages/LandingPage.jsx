import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import './LandingPage.css';

const LandingPage = () => {
  const navigate = useNavigate();

  const handleEnter = () => {
    const container = document.querySelector('.eclipse-container');
    if (container) {
      container.classList.add('fade-into-void');
    }
    setTimeout(() => navigate('/login'), 1200);
  };

  return (
    <div className="eclipse-container">
      {/* Background Starfield/Noise (subtle) */}
      <div className="space-void"></div>

      {/* The Eclipse */}
      <div className="eclipse-wrapper">
        <div className="corona-outer"></div>
        <div className="corona-inner"></div>
        <div className="black-hole">
          <div className="event-horizon"></div>
        </div>
      </div>

      {/* Content */}
      <div className="eclipse-content">
        <h1 className="eclipse-title">SHADOW SPIKE</h1>
        <p className="eclipse-subtitle">BEYOND THE HORIZON</p>
        
        <button className="btn-eclipse" onClick={handleEnter}>
          INITIALIZE <ArrowRight size={18} className="arrow-icon" />
        </button>
      </div>
    </div>
  );
};

export default LandingPage;
