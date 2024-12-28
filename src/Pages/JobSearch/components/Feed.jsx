import { feedData } from "../../../data/feedData2"

const Feed = () => {
 return (
    <>
    <div className=" w-[90%] mt-10  relative left-[100px]" > 
        <div className="flex gap-[1%] flex-wrap">
            {feedData.map((feed, index) => (
                 <div key={index} className=" w-[24%]  h-[310px] ">
                 <div className="bg-red-600 w-[100%]  br-[20px] relative rounded-[15px]">
                     <img src={feed.img} alt="profile"  className='h-[150px] object-fit'/>
                     <div className="w-[15%] h-[30%] rounded-full absolute left-[230px] top-[100px] ">
                         <img src={feed.profile}/>
                     </div>
                 </div>
               
                 <div>
                     <h1 className="font-Inter text-[20px] font-bold">{feed.title}</h1>
                     <p className="font-Inter text-[12px] font-semibold w-[90%]">{feed.description}</p>
                 </div>
                 </div>
            ))}
        </div>
        
    </div>
    
    </>
  )
}

export default Feed