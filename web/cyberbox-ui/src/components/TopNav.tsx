import { NavLink } from 'react-router-dom';

interface TopNavProps {
  health: string;
}

const NAV_LINKS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/alerts', label: 'Alerts', end: false },
  { to: '/rules', label: 'Rules', end: false },
  { to: '/investigate', label: 'Investigation', end: false },
  { to: '/audit', label: 'Audit', end: false },
];

export function TopNav({ health }: TopNavProps) {
  const isHealthy = health === 'ok';

  return (
    <nav className="top-nav">
      <img src="/cyberboxlogo.png" alt="CyberboxSIEM" className="top-nav__logo" />
      <ul className="top-nav__links">
        {NAV_LINKS.map(({ to, label, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              className={({ isActive }) =>
                `top-nav__link${isActive ? ' top-nav__link--active' : ''}`
              }
            >
              {label}
            </NavLink>
          </li>
        ))}
      </ul>
      <div className="top-nav__status">
        <span
          className={`top-nav__health-dot${isHealthy ? ' top-nav__health-dot--ok' : ' top-nav__health-dot--bad'}`}
          title={`System: ${health}`}
        />
        <span className="top-nav__health-label">{health}</span>
      </div>
    </nav>
  );
}
