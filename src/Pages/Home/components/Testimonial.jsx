import { Swiper, SwiperSlide } from 'swiper/react';
import 'swiper/css';
import 'swiper/css/free-mode';
import 'swiper/css/pagination';
import { FreeMode, Pagination } from 'swiper/modules';
import Person6 from "../../../assets/images/Person6.png"
import Vector from "../../../assets/images/Vector.png"

const WhatUsersSay = () => {
  return (
   <>
   <section className="w-[90%]  relative left-[70px] pt-[100px] pb-[30px]">
   <h1 className="text-bluecolor pb-[10px] font-Inter font-bold text-[30px]">What Our Users Say</h1>

      <Swiper
        slidesPerView={3}
        spaceBetween={10}
        freeMode={true}
       
        loop={true}
        pagination={{
          clickable: true,
        }}
        modules={[FreeMode, Pagination]}
        className="mySwiper"
      >
        <SwiperSlide>
        <div className="w-[100%] bg-orangecolor pb-[120px] rounded-[20px] ">
        
        <div className=" text-[11px] font-Inter text-greycolor relative top-[90px] left-[55px]">
         <p className="pb-[15px]">
         “As the CEO of Tech Innovators Inc., finding top-tier <br /> talent to join our team ias a top priority. Partnering <br /> with Linkprosoft has been a transformative <br /> experience for our hiring process.
         </p>
 
       <p>
       Linkprosoft impressed us with theirprofessionalism <br /> and deep understanding of our industry
       </p>
           </div>
 
           <div className="relative top-[90px] left-[10px] flex ">
             <img src={Person6} alt="" className="w-[25%]" />
         
         <div className="relative top-[58px] pl-[10px] leading-[20px] text-[16px] font-Inter">
         <h1 className=" font-bold text-[19px]">John, D</h1>
         <h1 className="font-semibold">CEO, Tech Innovators Inc.</h1>
         </div>
           </div>
        
         </div> 
        </SwiperSlide>

        <SwiperSlide>
        <div className="w-[100%] bg-orangecolor pb-[120px] rounded-[20px] ">
        
        <div className=" text-[11px] font-Inter text-greycolor relative top-[90px] left-[55px]">
         <p className="pb-[15px]">
         “As the CEO of Tech Innovators Inc., finding top-tier <br /> talent to join our team ias a top priority. Partnering <br /> with Linkprosoft has been a transformative <br /> experience for our hiring process.
         </p>
 
       <p>
       Linkprosoft impressed us with theirprofessionalism <br /> and deep understanding of our industry
       </p>
           </div>
 
           <div className="relative top-[90px] left-[10px] flex ">
             <img src={Person6} alt="" className="w-[25%]" />
         
         <div className="relative top-[58px] pl-[10px] leading-[20px] text-[16px] font-Inter">
         <h1 className=" font-bold text-[19px]">John, D</h1>
         <h1 className="font-semibold">CEO, Tech Innovators Inc.</h1>
         </div>
           </div>
        
         </div> 
        </SwiperSlide>

        <SwiperSlide>
        <div className="w-[100%] bg-orangecolor pb-[120px] rounded-[20px] ">
        
        <div className=" text-[11px] font-Inter text-greycolor relative top-[90px] left-[55px]">
         <p className="pb-[15px]">
         “As the CEO of Tech Innovators Inc., finding top-tier <br /> talent to join our team ias a top priority. Partnering <br /> with Linkprosoft has been a transformative <br /> experience for our hiring process.
         </p>
 
       <p>
       Linkprosoft impressed us with theirprofessionalism <br /> and deep understanding of our industry
       </p>
           </div>
 
           <div className="relative top-[90px] left-[10px] flex ">
             <img src={Person6} alt="" className="w-[25%]" />
         
         <div className="relative top-[58px] pl-[10px] leading-[20px] text-[16px] font-Inter">
         <h1 className=" font-bold text-[19px]">John, D</h1>
         <h1 className="font-semibold">CEO, Tech Innovators Inc.</h1>
         </div>
           </div>
        
         </div> 
        </SwiperSlide>

        <SwiperSlide>
        <div className="w-[100%] bg-orangecolor pb-[120px] rounded-[20px] ">
        
        <div className=" text-[11px] font-Inter text-greycolor relative top-[90px] left-[55px]">
         <p className="pb-[15px]">
         “As the CEO of Tech Innovators Inc., finding top-tier <br /> talent to join our team ias a top priority. Partnering <br /> with Linkprosoft has been a transformative <br /> experience for our hiring process.
         </p>
 
       <p>
       Linkprosoft impressed us with theirprofessionalism <br /> and deep understanding of our industry
       </p>
           </div>
 
           <div className="relative top-[90px] left-[10px] flex ">
             <img src={Person6} alt="" className="w-[25%]" />
         
         <div className="relative top-[58px] pl-[10px] leading-[20px] text-[16px] font-Inter">
         <h1 className=" font-bold text-[19px]">John, D</h1>
         <h1 className="font-semibold">CEO, Tech Innovators Inc.</h1>
         </div>
           </div>
        
         </div> 
        </SwiperSlide>

     
       
      </Swiper>
    
    <div className='flex items-center justify-end w-[95%] relative top-5 text-center'>
      <p className='font-bold font-Inter text-greencolor'>See more</p>
      <img src={Vector} alt="" className='pt-1 pl-2' />
    </div>
   </section>
   
   </>
  )
}

export default WhatUsersSay