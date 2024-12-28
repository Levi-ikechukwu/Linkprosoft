
// Import Swiper React components
import { Swiper, SwiperSlide } from 'swiper/react';

// Import Swiper styles
import 'swiper/css';
import 'swiper/css/free-mode';
import 'swiper/css/pagination';
// import required modules
import { FreeMode, Pagination } from 'swiper/modules';

const PopularSkills = () => {
 

  return (
    <>
    <section className="w-[90%] mx-auto pt-10 pb-[30px]">
      <h1 className="text-bluecolor font-Inter font-bold text-[30px]">Popular Skills Near You:</h1>
     
     
    
      <Swiper
        slidesPerView={4}
        spaceBetween={30}
        freeMode={true}
       
        loop={true}
        pagination={{
          clickable: true,
        }}
        modules={[FreeMode, Pagination]}
        className="mySwiper"
      >
        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>

        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>

        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>

        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>

        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>

        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>

        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>

        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>

        <SwiperSlide>
        <p className='w-[280px] font-Inter bg-greybg border-2 font-bold text-[24px] text-greycolor h-[30vh] flex items-center justify-center'>Programming & Tech</p>
        </SwiperSlide>
    
      </Swiper>
  

    </section>
    </>
  )
}

export default PopularSkills