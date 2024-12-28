import React from 'react'
import search from '../assets/images/search.png'
import profile from '../assets/images/profile.png'
import { Link } from 'react-router-dom'

const Navbar = () => {
  return (
    <>
    <header className='w-[100%] select-none  border-b-[#006FA3] border-b-4'>
    <nav className='flex align-center w-[90%] justify-between m-auto pt-9 pb-4' >
      <div className="text-3xl font-bold text-bluecolor font-Inter w-[15%] cursor-pointer"   >
                    <Link to='/'>Linkprosoft.</Link>
      </div>

      <div className='flex  w-[45%] justify-between flex-wrap'>
        <input type="text" placeholder='What skills are you looking for?' className='w-[91%] outline-none bg-[#D9D9D933] pl-[25px]'/>
        <div className='w-[9%] bg-[#03AEFF] rounded-md'> 
        <img src={search} className=' w-[40%] m-auto relative top-[10px]'  alt="" />
        </div>
      </div>

      <div className='flex w-[22%] flex align-center justify-between'>
        <a href="/" className='bg-[#03AEFF] font-Inter text-white justify py-2 px-5 rounded-md'>Post Gigs</a>
        <a href="/" className='bg-[#006FA3] font-Inter text-white justify py-2 px-5 rounded-md '>Sign In</a>
        <div className='w-[16%] h-[40px] flex rounded-full align-center justify-center '>
        <img src={profile} alt="" className='rounded-full'/>
        </div>
      </div>
      </nav>
    </header>
    </>
  )
}

export default Navbar