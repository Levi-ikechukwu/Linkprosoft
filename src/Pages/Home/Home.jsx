
import Navbar from "./components/Navbar"
import Hero from "./components/Hero"
import HowitWorks from "./components/HowitWorks"
import PopularSkills from "./components/PopularSkills"
import WhychooseUs from "./components/WhychooseUs"
import Testimonial from "./components/Testimonial"
import CallToAction from "./components/CallToAction"
import Footer from "./components/Footer"

const Home = () => {
  return (
    <>
    
    <Navbar/>
    <Hero></Hero>
    <PopularSkills></PopularSkills>
    <HowitWorks></HowitWorks>
    <WhychooseUs></WhychooseUs>
    <Testimonial></Testimonial>
    <CallToAction/>
    <Footer></Footer>
    </>
  )
}

export default Home