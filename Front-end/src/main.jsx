import { StrictMode, lazy, Suspense } from 'react';
import { createRoot } from 'react-dom/client'
import './index.css'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import UserProvider from './contexts/User';
import Loader from './components/Loader.jsx';
import { LoadingProvider } from './contexts/LoadingContext.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';

const Home = lazy(() => import('./Pages/Home/Home.jsx'))
const Error = lazy(() => import('./components/Error.jsx'))
const JobDetails = lazy(() => import('./Pages/JobDetails/JobDetails.jsx'))
const EmployerDashboard = lazy(() => import('./Pages/EmployerDashboard/EmployerDashboard.jsx'))
const Recommended = lazy(() => import('./Pages/UserDashboard/Routes/Recommended.jsx'))
const SavedGigs = lazy(() => import('./Pages/UserDashboard/Routes/SavedGigs.jsx'))
const Notifications = lazy(() => import('./Pages/UserDashboard/Routes/Notifications.jsx'))
const Pending = lazy(() => import('./Pages/UserDashboard/Routes/Pending.jsx'))
const Completed = lazy(() => import('./Pages/UserDashboard/Routes/Completed.jsx'))
const Rejected = lazy(() => import('./Pages/UserDashboard/Routes/Rejected.jsx'))
const Onboarding = lazy(() => import('./Pages/OnBoarding/Onboarding.jsx'))
const SignUpAs = lazy(() => import('./Pages/Login&SignUp/SignUpAs.jsx'))
const Login = lazy(() => import('./Pages/Login&SignUp/Login.jsx'))
const SignUp = lazy(() => import('./Pages/Login&SignUp/SignUp.jsx'))
const GigsOptionsBody = lazy(() => import('./Pages/UserDashboard/components/GigsOptionsBody.jsx'))
const Settings = lazy(() => import('./Pages/UserDashboard/Routes/Settings.jsx'))
const Help = lazy(() => import('./Pages/UserDashboard/Routes/Help.jsx'))
const CustomerSupport = lazy(() => import('./Pages/UserDashboard/Routes/CustomerSupport.jsx'))
const SettingsBody = lazy(() => import('./Pages/UserDashboard/components/SettingsBody.jsx'))
const PasswordReset = lazy(() => import('./Pages/UserDashboard/Routes/PasswordReset.jsx'))
const UserDashboard = lazy(() => import('./Pages/UserDashboard/UserDashboard.jsx'))
const EditProfile = lazy(() => import('./Pages/UserDashboard/Routes/EditProfile.jsx'))
const Certifications = lazy(() => import('./Pages/UserDashboard/Routes/Certifications.jsx'))
const Post = lazy(() => import('./Pages/UserDashboard/Routes/Post.jsx'))
const Projects = lazy(() => import('./Pages/UserDashboard/Routes/Projects.jsx'))
const ProjectsBody = lazy(() => import('./Pages/UserDashboard/components/ProjectsBody.jsx'))
const Billing = lazy(() => import('./Pages/UserDashboard/Routes/Billing.jsx'))
const NotificationSidebar = lazy(() => import('./Pages/UserDashboard/Routes/NotificationSidebar.jsx'))
const Report = lazy(() => import('./Pages/UserDashboard/Routes/Report.jsx'))
const ProjectSidebar = lazy(() => import('./Pages/UserDashboard/Routes/ProjectSidebar.jsx'))
const ChatArea = lazy(() => import('./Pages/UserDashboard/Routes/ChatArea.jsx'))
const DashboardBody = lazy(() => import('./Pages/UserDashboard/components/DasboardBody.jsx'))
const GigPosting = lazy(() => import('./Pages/GigPosting/GigPosting.jsx'))
const ChooseTitle = lazy(() => import('./Pages/GigPosting/Routes/ChooseTitle.jsx'))

const router = createBrowserRouter([
  {
    path: '/',
    element: <Home />,
    errorElement: <Error />,
  },
  {
    path: '/user-dashboard',
    element: <ProtectedRoute> <UserDashboard /> </ProtectedRoute>,
    children: [
      { index: true, element: <DashboardBody /> },
      {
        path: 'dashboard',
        element: <DashboardBody />,
        children: [
          { path: 'message', element: <ChatArea /> },
        ],
      },
      { path: 'certifications', element: <Certifications /> },
      { path: 'post', element: <Post /> },
      { path: 'projects', element: <ProjectSidebar /> },
      { path: 'billing', element: <Billing /> },
      { path: 'notifications', element: <NotificationSidebar /> },
      { path: 'report', element: <Report /> },
      { path: 'settings', element: <Settings /> },
      {
        path: 'gigs-options',
        element: <GigsOptionsBody />,
        children: [
          { index: true, element: <Recommended /> },
          { path: 'recommended', element: <Recommended /> },
          { path: 'saved-gigs', element: <SavedGigs /> },
          { path: 'notifications', element: <Notifications /> },
        ],
      },
      {
        path: 'projects',
        element: <ProjectsBody />,
        children: [
          { index: true, element: <Pending /> },
          { path: 'pending', element: <Pending /> },
          { path: 'completed', element: <Completed /> },
          { path: 'rejected', element: <Rejected /> },
        ],
      },
      {
        path: 'settings',
        children: [
          { index: true, element: <SettingsBody /> },
          { path: 'edit-profile', element: <EditProfile /> },
          { path: 'password-reset', element: <PasswordReset /> },
          { path: 'help', element: <Help /> },
          { path: 'customers-support', element: <CustomerSupport /> },
        ],
      },
    ],
  },
  { path: '/employer-dashboard', element: <ProtectedRoute> <EmployerDashboard /> </ProtectedRoute> },

  { path: '/job-details', element: <JobDetails /> },

  { path: '/on-boarding', element: <Onboarding /> },

  { path: '/signup-as', element: <SignUpAs /> },

  { path: '/register', element: <SignUp /> },

  { path: '/login', element: <Login /> },

  {
    path: 'gig-posting', element: <GigPosting />,
    children: [
      { index: true, element: <ChooseTitle /> },
    ],
  },
]);

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <UserProvider>
      <LoadingProvider>
        <Suspense fallback={<Loader />}>
          <RouterProvider router={router} />
        </Suspense>
      </LoadingProvider>
    </UserProvider>
  </StrictMode>
);