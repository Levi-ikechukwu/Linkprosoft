import Certifications from '../Routes/Certifications'
import Settings from '../Routes/Settings'
import Post from '../Routes/Post'
import Billing from '../Routes/Billing'
import NotificationSidebar from '../Routes/NotificationSidebar'
import Report from '../Routes/Report'
import ProjectSidebar from '../Routes/ProjectSidebar'
import Dashboard from '../Routes/Dashboard'

const Main = ({ isActive }) => {
    return (
        <main className='w-full flex justify-end'>

            {isActive === "dashboard"
                ? <Dashboard />
                : isActive === "certifications"
                    ? <Certifications />
                    : isActive === "post"
                        ? <Post />
                        : isActive === "projects"
                            ? <ProjectSidebar />
                            : isActive === "billing"
                                ? <Billing />
                                : isActive === "notifications"
                                    ? <NotificationSidebar />
                                    : isActive === "report"
                                        ? <Report />
                                        : isActive === "settings"
                                            ? <Settings />
                                            : "No such path found"
            }
        </main>
    )
}

export default Main
