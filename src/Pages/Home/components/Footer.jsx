import { FaFacebook } from "react-icons/fa";
import { FaLinkedin } from "react-icons/fa";
import { LuCopyright } from "react-icons/lu";
import { FaXTwitter } from "react-icons/fa6";
import {categories, about, support, resources} from "../../../data/FooterData.js"
import { Link } from "react-router-dom";

const Footer = () => {
  return (
    <>
    <footer className="w-[100%] bg-bluecolor pb-[180px] relative z-10 overflow-hidden ">
      <div className="w-[85%] mx-auto flex justify-between relative top-10 gap-5 ">
        <div className="relative top-[100px] w-[30%]">
          <h1 className="font-Inter text-white text-[30px] pb-5 font-bold">Linkprosoft.</h1>
          <p className="pb-2 font-bold text-white font-Inter text-17px">Follow Us</p>

        <div className="flex gap-3 ">
           <FaLinkedin className="   text-white text-[25px]" />
           <FaXTwitter className="   text-white text-[25px]"/>
            <FaFacebook className="    text-[25px]"/>
        </div>
        </div>


        <div className="flex w-[60%] relative justify-between top-[50px]">
          <div>
            <h1 className="font-semibold text-white list-disc font-Inter text-[13px]">Categories</h1>
            <ul className="font-semibold text-white pl-8 list-disc font-Inter text-[12px]">
              {categories.map((category, index) => (
                <li key={index}><Link>{category}</Link></li>
              ))}
              </ul>
          </div>

          <div>
            <h1 className="font-semibold text-white list-disc font-Inter text-[13px]">About</h1>
            <ul className="font-semibold text-white pl-8 list-disc font-Inter text-[12px]">
             {about.map((about, index) => (
              <li key={index}><Link>{about}</Link></li>
             ))}
              </ul>
          </div>

          <div>
            <h1 className="font-semibold text-white list-disc font-Inter text-[13px]">Support</h1>
            <ul className="font-semibold text-white pl-8 list-disc font-Inter text-[12px]">
              {support.map((support, index) => (
                <li key={index}><Link>{support}</Link></li>
              ))}
              </ul>
          </div>

          <div>
            <h1 className="font-semibold text-white list-disc font-Inter text-[13px]">Resources</h1>
            <ul className="font-semibold text-white pl-8 list-disc font-Inter text-[12px]">
              {resources.map((resource, index) => (
                <li key={index}><Link>{resource}</Link></li>
              ))}
              
              </ul>
          </div>
        </div>
      </div>
      <hr className="relative top-[160px]"/>
    <div  className="relative top-[170px] left-[1040px] flex text-center items-center  text-white">
    <LuCopyright />
    <h1 className=" text-[14px]  font-Inter pl-1">  2024 Linkprosoft. All Rights Reserved.</h1>
    
    </div>
    </footer>
    
    </>
  )
}

export default Footer