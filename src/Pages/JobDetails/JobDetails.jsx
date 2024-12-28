
import Footer from '../Home/components/Footer'
import PrevNext from '../JobSearch/components/PrevNext'
import Booking from './components/Booking'
import Feed from './components/Feed'
import Navbar from './components/Navbar2'
import SideBar from './components/SideBar'
import Suggested from './components/Suggested'

const JobDetails = () => {
  return (
   <>
   <Navbar/>
   <Suggested/>
   <Booking/>
   <Feed/>
   <SideBar/>
   <PrevNext/>
   <Feed/>
   <Footer/>
   </>
  )
}

export default JobDetails