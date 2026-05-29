import { NavLink, Outlet } from 'react-router-dom';

export default function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <p className="eyebrow">SecureScope</p>
          <h1>Security Dashboard</h1>
        </div>
        <nav className="nav-list" aria-label="Main navigation">
          <NavLink to="/">Dashboard</NavLink>
          <NavLink to="/pc-security">PC Security</NavLink>
          <NavLink to="/website-security">Website Security</NavLink>
        </nav>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
