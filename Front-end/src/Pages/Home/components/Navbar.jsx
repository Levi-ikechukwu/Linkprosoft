import { Link } from 'react-router-dom';
import { RiMenu5Fill } from "react-icons/ri";
import { IoCloseSharp } from "react-icons/io5";
import { useState } from 'react';


const Navbar = () => {
  const [isToggled, setIsToggled] = useState(false);

  const handleMenu = () => {
    setIsToggled(() => !isToggled);
  }

  return (
    <>
      <header className="bg-white w-[100%] sticky z-[1000] top-0 left-0 right-0">
        <nav className="w-[90%] lg:w-[90%] py-[15px] mx-auto flex justify-between items-center">
          <div className="text-4xl font-bold text-bluecolor font-Inter cursor-pointer">
            <Link to='/'>Linkprosoft.</Link>
          </div>

          <div className={`${isToggled ? 'top-[100%]' : 'top-[-1000%] z-[1000]'} left-0 flex flex-col lg:flex-row w-full lg:top-0 py-6 lg:py-0 duration-[1s] bg-bluecolor lg:bg-transparent absolute lg:relative items-center justify-between font-Inter text-greycolor text-[17px] `}>
            <div className={`flex flex-col lg:flex-row justify-around items-center gap-4 lg:gap-0 mb-10 lg:mb-0 w-[80%] lg:w-[50%] xl:w-[40%] mx-auto text-white lg:text-black`}>
              <Link to="/">Home</Link>
              <Link to="/UserDashboard">About</Link>
              <Link to="/JobDetails">How It Works</Link>
              <Link to="/EmployerDashboard">Contact Us</Link>
            </div>

            <div className="flex gap-3 text-[15px]">
              <Link to="/signup" className="bg-bluecolor lg:hover:bg-transparent border hover:border-bluecolor text-white hover:text-bluecolor font-Inter py-[10px] px-[25px] rounded-tl-[40px] rounded-br-[40px]">Sign Up</Link>
              <Link to="/Login" className="border text-white lg:text-bluecolor border-white lg:border-bluecolor lg:hover:bg-bluecolor hover:text-white font-Inter py-[10px] px-[25px] rounded-tl-[40px] rounded-br-[40px]">Login</Link>
            </div>
          </div>


          <div className='block lg:hidden' onClick={handleMenu}>
            {isToggled ? <IoCloseSharp className="text-bluecolor text-2xl" /> : <RiMenu5Fill className='text-bluecolor text-2xl' />}
          </div>
        </nav>
      </header>
    </>
  )
}

export default Navbar