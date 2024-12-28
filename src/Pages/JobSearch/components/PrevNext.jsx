
import next from "../../../assets/images/arrow1.svg"
import prev from "../../../assets/images/arrow2.svg"

const PrevNext = () => {
  return (
   <>
        <div className="white select-none bg-white w-[90%] relative left-[100px] flex items-center  justify-between h-[90px] align-center">
            <div><p className="font-Inter text-[15px] font-bold">showing 15 results</p></div>
            <div className=" w-[35%] flex items-center gap-[3%] flex-wrap">
                <div className="flex align-center justify-center w-[29%] bg-black px-3 py-2 rounded-full">
                    <img src={next} alt="" />
                    <p className="font-Inter font-semibold text-[15px] pl-2 text-white ">Previous</p>
                </div>

                <div className="flex text-center justify-between font-Inter font-bold h-[40px] text-[17px] w-[35%]  bg-[#F4F4F4] rounded-full px-4 text-[rgba(0, 0, 0, 0.67)] ">
                    <a href="/" className="pt-2">1</a>
                    <a href="/" className=" bg-[#D9D9D9] rounded-full w-[40px] h-[40px] pt-2 text-center ">2</a>
                    <a href="/" className="pt-2">3</a>
                    <a href="/" className="pt-2">4</a>

                
                </div>

                <div className="flex align-center justify-center w-[29%] bg-black px-3 py-2 rounded-full">

                    <p className="font-Inter font-semibold text-[15px] pr-2 text-white ">Next</p>
                    <img src={prev} alt="" />
                </div>
            </div>
        </div>
   </>
  )
}

export default PrevNext