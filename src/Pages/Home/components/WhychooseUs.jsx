import Verified from "../../../assets/images/Verified.png"
import Notify from "../../../assets/images/Notification.png"
import Payment from "../../../assets/images/Payment.png"
import Review from "../../../assets/images/Review.png"
import Person5 from "../../../assets/images/Person5.png"

const WhychooseUs = () => {
  return (
   <section className="mx-auto w-[90%] pt-[45px]">
     <h1 className="text-bluecolor pb-[10px] font-Inter font-bold text-[33px]">Why Choose Linkprosoft?</h1>

    <div className="flex w-[100%] gap-3 flex-wrap">
      <div className="flex flex-col  gap-5 w-[35.3%] items-center ">
        <div className="border-[2px] py-[30px]  px-[50px] text-center leading-[35px]">
            <img src={Verified} alt="" className="mx-auto pb-[10px]" />
            <h1 className="font-Inter text-[20px] font-bold  text-greycolor">Verified Proffesionals</h1>
            <p className="font-Inter font-semibold text-[13px] text-greycolor">All professionals are vetted for quality.</p>
        </div>

        <div className="border-[2px] py-[30px]  px-[78px]  leading-[35px]">
            <img src={Notify} alt="" className="mx-auto pb-[10px]" />
            <h1 className="font-Inter text-center text-[20px] font-bold  text-greycolor">Real-Time Updates</h1>
            <p className="font-Inter leading-[17px] font-semibold text-[13px] text-greycolor">Stay updated with real-time notifications and tracking</p>
        </div>

      
      </div>

      <div className="flex flex-col   relative top-[70px] gap-5 w-[35.3%] items-center">
        <div className="border-[2px] py-[20px]  px-[78px] text-center leading-[35px]">
            <img src={Payment} alt="" className="mx-auto pb-[10px]" />
            <h1 className="font-Inter text-[20px] font-bold  text-greycolor">Secure Payments</h1>
            <p className="font-Inter font-semibold text-[13px] text-greycolor">Hassle-free and secure payment gateway.</p>
        </div>

        <div className="border-[2px] py-[20px]  px-[78px] text-center leading-[35px]">
            <img src={Review} alt="" className="mx-auto pb-[10px]" />
            <h1 className="font-Inter text-[20px] font-bold  text-greycolor">User Reviews</h1>
            <p className="font-Inter font-semibold text-[12px] text-greycolor">Check reviews and ratings from other users.</p>
        </div>

      
      </div>

      <div className="flex flex-col   relative top-[80px]   w-[27.3%] items-center">
        <img src={Person5} alt="" className="w-[100%] ml-[14px] "  />
      </div>
    </div>

   </section>
  )
}

export default WhychooseUs