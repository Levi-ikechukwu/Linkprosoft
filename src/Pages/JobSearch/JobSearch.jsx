import Footer from "../Home/components/Footer"
import Navbar from "../JobDetails/components/Navbar2"
import Suggested from "../JobDetails/components/Suggested"
import Feed from "./components/Feed"
import PrevNext from "./components/PrevNext"

const JobSearch = () => {
  return (
    <>
    <Navbar/>
    <Suggested/>
    <Feed/>
    <PrevNext/>
    <Feed/>
    <Footer/>
    </>
  )
}

export default JobSearch