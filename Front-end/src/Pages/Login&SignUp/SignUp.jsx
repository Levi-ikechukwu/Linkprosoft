import { useState } from 'react'
import HeaderBanner from './components/HeaderBanner'
import OurLogo from '../../assets/images/linkprosoft-logo.png'
import { Link, useNavigate } from 'react-router-dom'
import { FaLinkedin } from "react-icons/fa";
import { FcGoogle } from "react-icons/fc";
import { FaRegEye, FaRegEyeSlash } from "react-icons/fa";
import { ToastContainer, toast } from 'react-toastify'
import { useAuth } from '../../contexts/User';

const SignUp = () => {
    const { signup, signUpUserAs } = useAuth();
    const navigate = useNavigate();
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [compName, setCompName] = useState('');
    const [userType, setUserType] = useState(signUpUserAs);
    const [passwordShowing, setPasswordShowing] = useState(false);
    const [passwordType, setPasswordType] = useState('password');

    const handleFormSubmit = async (e) => {
        e.preventDefault();

        try{
            const response = await signup({ firstName, lastName, email, password, compName, userType });
            console.log(response);
            
            if (response.success && response.user_type === 'employer') {
                toast.success(response.message);
                setTimeout(() => {
                    navigate('/user-dashboard')
                }, 2000);
            }
    
            if (response.success && response.user_type === 'professional') {
                toast.success(response.message);
                setTimeout(() => {
                    navigate('/employer-dashboard')
                }, 2000);
            }
    
            if (!response.success) {
                toast.warning(response.message);
            }
        } catch(error){
            console.error(error.message);
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
                btnColor='#ffffff'
                btnTextColor='#006FA3'
                pageHeader={"Login"}
                pageLink={"login"}
            />

            <section className="w-full lg:bg-[#F6F6F6] min-h-[90vh] lg:flex lg:items-center">
                <div className="w-[85%] lg:w-[85%] mx-auto flex justify-between items-center py-5 2xl:h-dvh ">
                    <div className='w-[50%] lg:w-[40%] mx-auto hidden lg:block px-4'>
                        <img src={OurLogo} alt="" className='w-full lg:w-[80%] xl:w-[60%] mx-auto' />
                        <p className='w-full opacity-50 text-center mt-3'>Linkprosoft bridging the gap between employers and employees</p>
                    </div>

                    <div className='w-full lg:w-[55%] xl:w-[50%] mx-auto bg-transparent lg:bg-white rounded-none lg:rounded-lg shadow-none lg:shadow-lg lg:p-3 lg:px-6 lg:py-6'>
                        <h2 className='hidden lg:block text-[1.5rem] font-Inter font-[800] mb-3 text-center w-full md:mb-3 text-bluecolor'>Sign Up</h2>

                        <form onSubmit={handleFormSubmit}>
                            <div className='md:flex gap-4 items-center'>
                                <div className='w-full'>
                                    <label htmlFor="firstName" className='block text-gray-700 font-medium mb-1 md:text-[22px] lg:text-[16px]'>First Name</label>
                                    <input
                                        value={firstName}
                                        onChange={(e) => setFirstName(e.target.value)}
                                        type="text"
                                        name="firstName"
                                        id="firstName"
                                        className='w-full text-lg lg:text-base px-2 py-1.5 mb-3 border-none rounded-md focus:outline-none focus:ring-2 focus:ring-[#0A66C2] bg-[#f6f6f6]'
                                    />
                                </div>

                                <div className='w-full'>
                                    <label htmlFor="lastName" className='block text-gray-700 font-medium mb-1 md:text-[22px] lg:text-[16px]'>Last Name</label>
                                    <input
                                        value={lastName}
                                        onChange={(e) => setLastName(e.target.value)}
                                        type="text"
                                        name="lastName"
                                        id="lastName"
                                        className='w-full text-lg lg:text-base px-2 py-1.5 mb-3 border-none rounded-md focus:outline-none focus:ring-2 focus:ring-[#0A66C2] bg-[#f6f6f6]'
                                    />
                                </div>
                            </div>

                            <div className='md:flex gap-4 items-center'>
                                <div className='w-full'>
                                    <label htmlFor="email" className='block text-gray-700 font-medium mb-1 md:text-[22px] lg:text-[16px]'>Email</label>
                                    <input
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        type="email"
                                        name="email"
                                        id="email"
                                        className='w-full text-lg lg:text-base px-2 py-1.5 mb-3 border-none rounded-md focus:outline-none focus:ring-2 focus:ring-[#0A66C2] bg-[#f6f6f6]'
                                    />
                                </div>

                                <div className='w-full'>
                                    <label htmlFor="password" className='block text-gray-700 font-medium mb-1 md:text-[22px] lg:text-[16px]'>Password</label>

                                    <div className='flex items-center bg-[#f6f6f6] rounded-md'>
                                        <input type={passwordType} name="password" id="password" required
                                            onChange={(e) => setPassword(e.target.value)}
                                            value={password} className='w-full text-lg lg:text-base px-2 py-2 lg:py-1.5 border-none focus:outline-none bg-transparent' />

                                        <div className='w-[10%] flex items-center pr-2 text-center justify-center py-2'>
                                            {passwordShowing ?
                                                <FaRegEyeSlash className='text-base cursor-pointer' onClick={handleShowPassword} /> :
                                                <FaRegEye className='text-base cursor-pointer' onClick={handleShowPassword} />
                                            }
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className='md:flex gap-4 items-center'>
                                <div className='w-full'>
                                    <label htmlFor="compName" className='block text-gray-700 font-medium mb-1 md:text-[22px] lg:text-[16px]'>Company Name</label>
                                    <input
                                        value={compName}
                                        onChange={(e) => setCompName(e.target.value)}
                                        type="text"
                                        name="compName"
                                        id="compName"
                                        className='w-full text-lg lg:text-base px-2 py-1.5 mb-3 border-none rounded-md focus:outline-none focus:ring-2 focus:ring-[#0A66C2] bg-[#f6f6f6]'
                                    />
                                </div>

                                <div className='w-full'>
                                    <label htmlFor="userType" className='block text-gray-700 font-medium mb-1 md:text-[22px] lg:text-[16px]'>User Type</label>
                                    <input
                                        value={userType}
                                        onChange={(e) => setUserType(e.target.value)}
                                        type="text"
                                        name="userType"
                                        id="userType"
                                        placeholder='employer/professional'
                                        className='w-full text-lg lg:text-base px-2 py-1.5 border-none rounded-md focus:outline-none focus:ring-2 focus:ring-[#0A66C2] bg-[#f6f6f6]'
                                    />
                                </div>
                            </div>

                            <div className="flex flex-col sm:flex-row justify-between sm:items-center lg:gap-2 mt-5 lg:mt-1">
                                <div className='flex items-center gap-1 cursor-pointer '>
                                    <input type="checkbox" name="" id="checkbox" className='cursor-pointer' />
                                    <label htmlFor='checkbox' className='font-[400] font-Inter text-sm text-black cursor-pointer'>Keep me logged in.</label>
                                </div>

                                <div className="block lg:flex-col flex-nowrap justify-between items-center lg:items-start sm:gap-[1%] font-Inter my-2">
                                    <p className='text-sm'>Already have an account? {" "}
                                        <button onClick={() => navigate('/login')} className='text-blue-500 underline hover:text-blue-700'> Sign In</button>
                                    </p>
                                </div>
                            </div>

                            <div className='w-full sm:w-[50%]lg:w-full mx-auto'>
                                <button type='submit' className="px-4 py-2 w-full bg-[#006FA3] text-base font-medium rounded-md hover:bg-[#0A66C2] transition mt-6 mb-3 text-[#ffffff]">Sign Up</button>
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

export default SignUp
