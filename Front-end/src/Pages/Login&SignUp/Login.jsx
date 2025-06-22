import React, { useState } from 'react'
import HeaderBanner from './components/HeaderBanner'
import OurLogo from '../../assets/images/linkprosoft-logo.png'
import { FaLinkedin, FaRegEye, FaRegEyeSlash } from "react-icons/fa";
import { FcGoogle } from "react-icons/fc";
import { Link, useNavigate } from 'react-router-dom'
import axios from "axios"
import { ToastContainer, toast } from 'react-toastify'
import { useAuth } from '../../contexts/User';

const Login = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState({})
  const [passwordShowing, setPasswordShowing] = useState(false);
  const [passwordType, setPasswordType] = useState('password');
  const { login } = useAuth();
  axios.defaults.withCredentials = true;

  const handleSubmit = async (e) => {
    e.preventDefault()
    let formErrors = {}

    if (!email) {
      formErrors.email = "Please Enter Your Email Address"
    } else if (!/\S+@\S+\.\S+/.test(email)) {
      formErrors.email = "Email is Invalid"
    }

    if (!password) {
      formErrors.password = "Please Enter Your Password"
    } else if (password.length < 6) {
      formErrors.password = "Password must be at least 6 seven characters"
    }
    setError(formErrors)

    if (Object.keys(formErrors).length === 0) {
      const res = await login({ email, password },);
      if (res.path === 'employer') {
        setTimeout(() => {
          navigate("/user-dashboard");
          setEmail("")
          setPassword("")
        }, 2000);
      } else if (res.path === 'professional') {
        setTimeout(() => {
          navigate('/employer-dashboard');
          setEmail("")
          setPassword("")
        }, 2000);
      }
    }

  }

  const handleShowPassword = () => {
    setPasswordShowing(() => !passwordShowing);
    const checkType = document.getElementById('password').type;
    if (checkType === 'password') {
      setPasswordType(prev => prev = 'text');
    } else if (checkType === 'text') {
      setPasswordType(prev => prev = 'password');
    }
  }

  return (
    <>
      <HeaderBanner
        bgColor='#000000'
        logoColor='#ffffff'
        btnColor='#006FA3'
        btnTextColor='#ffffff'
        pageHeader={"Sign Up"}
        pageLink={"register"}
      />

      <section className="w-full lg:bg-[#F6F6F6] min-h-[90vh] font-Inter lg:flex lg:items-center">
        <div className="w-[85%] lg:w-[80%] mx-auto flex justify-between items-center pt-10 pb-5 lg:py-5 ">
          <div className='w-[50%] lg:w-[40%] mx-auto hidden lg:block px-4'>
            <img src={OurLogo} alt="" className='w-full mx-auto' />
            <p className='w-full opacity-50 text-center mt-3'>Linkprosoft bridging the gap between employers and employees</p>
          </div>

          <div className='w-full lg:w-[55%] xl:w-[50%] mx-auto bg-transparent lg:bg-white rounded-none lg:rounded-lg shadow-none lg:shadow-lg lg:p-3 lg:px-10 lg:py-8'>
            <h2 className='text-[1.6rem] font-Inter font-[800] leading-[40px mb-3 text-center lg:text-left block md:w-full md:mb-3 xl:max-w-[85%]'>Log in,
              start <span className='text-[#4093BA]'>advertising</span> and get <span className='text-[#4093BA]'>working</span>
            </h2>

            <form action="" onSubmit={handleSubmit} className=''>
              <div className='relative mb-3'>
                <label htmlFor="" className='block text-gray-700 font-medium mb-1 md:text-[22px] lg:text-[16px]'>Email</label>
                <input type="email" name="email" id="email" required
                  onChange={(e) => setEmail(e.target.value)}
                  onFocus={() => setError({ ...error, email: null })}
                  value={email}
                  className='w-full text-lg lg:text-base px-2 py-2 border-none rounded-md focus:outline-none focus:ring-2 focus:ring-[#0A66C2] bg-[#f6f6f6] '
                />
                <p className='text-xs text-red-600'>{error.email}</p>
              </div>

              <div className='relative'>
                <label htmlFor="" className='block text-gray-700 font-medium mb-1 md:text-[22px] lg:text-[16px]'>Password</label>
                <div className='flex items-center bg-[#f6f6f6] rounded-md'>
                  <input type={passwordType} name="password" id="password" required
                    onChange={(e) => setPassword(e.target.value)}
                    onFocus={() => setError({ ...error, password: null })}
                    value={password} className='w-full text-lg lg:text-base px-2 py-2 lg:py-1.5 border-none focus:outline-none bg-transparent' />

                  <div className='w-[10%] flex items-center pr-2 text-center justify-center py-2'>
                    {passwordShowing ?
                      <FaRegEyeSlash className='text-base' onClick={handleShowPassword} /> :
                      <FaRegEye className='text-base' onClick={handleShowPassword} />
                    }
                  </div>
                </div>
                <p className='text-xs text-red-600'>{error.password}</p>
              </div>

              <div className="flex items-center justify-between mt-5">
                <div className='flex items-center gap-1 cursor-pointer'>
                  <input type="checkbox" name="" id="checkbox" className='cursor-pointer' />
                  <label htmlFor='checkbox' className='font-[400] font-Inter text-sm text-black cursor-pointer'>Keep me logged in.</label>
                </div>

                <Link to='' className='text-blue-500 underline hover:text-blue-700 active:text-blue-800 text-sm'>Forgotten Password?</Link>
              </div>

              <div className='w-full'>
                <button type='submit' className="px-4 py-2 w-full bg-gradient-to-r from-[#006FA3] to-[#4DC6FF] text-base font-medium rounded-md hover:bg-[#0A66C2] transition mt-6 mb-3 text-[#ffffff]">Sign In</button>
              </div>

              <div className="flex items-center justify-center gap-3 mt-4">
                <div className="bg-white shadow-xl drop-shadow-xl w-max rounded-full px-2 py-2 cursor-pointer">
                  <FaLinkedin className='text-2xl text-bluecolor' />
                </div>
                <div className="bg-white shadow-xl drop-shadow-xl w-max rounded-full px-2 py-2 cursor-pointer">
                  <FcGoogle className='text-2xl' />
                </div>
              </div>

            </form>
          </div>
        </div>
        <ToastContainer />
      </section>
    </>
  )
}

export default Login