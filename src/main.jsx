import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import JobDetails from './Pages/JobDetails/JobDetails.jsx'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import Home from './Pages/Home/Home.jsx'
import Error from './components/Error.jsx'
import JobSearch from './Pages/JobSearch/JobSearch.jsx'

const router = createBrowserRouter([
  {
    path: '/',
    element: <Home />, // This is the root component
    errorElement: <Error />,
  },
  {
    path: '/JobDetails',
    element: <JobDetails />,
  },
  {
    path: '/JobSearch',
    element: <JobSearch/>,
  }
])

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>
)