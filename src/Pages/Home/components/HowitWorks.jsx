import Arrow from "../../../assets/images/Arrow.svg"

const HowitWorks = () => {
  return (
  <>
    <section className="w-[85%]  relative left-[70px] pt-[30px] pb-[30px]">
    <h1 className="text-bluecolor pb-[10px] font-Inter font-bold text-[30px]">How Linkprosoft Works:</h1>

    <div className="flex items-center justify-evenly w-[100%]">
      <div className="border-3 border rounded-full flex items-center justify-center font-Inter font-semibold text-bluecolor text-[30px] w-[80px] h-[80px] border-bluecolor">1</div>
      <img src={Arrow} alt="" />
      <div className="border-3 border rounded-full flex items-center justify-center font-Inter font-semibold text-bluecolor text-[30px] w-[80px] h-[80px] border-bluecolor">2</div>
      <img src={Arrow} alt="" />
      <div className="border-3 border rounded-full flex items-center justify-center font-Inter font-semibold text-bluecolor text-[30px] w-[80px] h-[80px] border-bluecolor">3</div>
    </div>

    <div className="flex  flex-row justify-between pt-[5px] items-center w-[100%]">
      <div className="w-[33.3%] text-center relative right-[80px]">
        <h1 className="text-[25px] font-bold text-greycolor">Post Your Need</h1>
        <p className="text-[14px] text-greycolor">Describe the service you need.</p>
      </div>

      <div className="w-[33.3% text-center">
        <h1 className="text-[25px] font-bold text-greycolor">Match with Professionals</h1>
        <p className="text-[14px] text-greycolor">Get matched with the best professionals nearby</p>
      </div>

      <div className="w-[33.3%] font-Inter text-center relative left-[95px] leading-[30px]" >
        <h1 className="text-[25px] font-bold text-greycolor">Hire & Get It Done</h1>
        <p className="text-[14px] text-greycolor">Hire the professionals and get the job done.</p>
      </div>
    </div>
    </section>
  </>
  )
}

export default HowitWorks