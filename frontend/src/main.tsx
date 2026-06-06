import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import App from './App';
import PcSecurityPage from './domains/pc-security/PcSecurityPage';
import WebsiteScanDetailPage from './domains/website-security/WebsiteScanDetailPage';
import WebsiteSecurityPage from './domains/website-security/WebsiteSecurityPage';
import DashboardPage from './pages/DashboardPage';
import './styles.css';

const queryClient = new QueryClient();

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'pc-security', element: <PcSecurityPage /> },
      { path: 'website-security', element: <WebsiteSecurityPage /> },
      { path: 'website-scans/:id', element: <WebsiteScanDetailPage /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
);
