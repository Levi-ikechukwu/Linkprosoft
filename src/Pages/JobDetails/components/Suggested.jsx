import  { useState } from 'react';
import arrow from '../assets/images/arrow.png';

const Suggested = () => {
  const [openDropdown, setOpenDropdown] = useState(null);

  const toggleDropdown = (dropdownId) => {
    setOpenDropdown(openDropdown === dropdownId ? null : dropdownId);
  };

  return (
    <section className="w-full select-none pt-[30px]">
      <div className="w-[85%] m-auto relative">
        <h1 className="font-Inter font-bold pb-2 " >Suggested</h1>
        <div className="flex align-center justify-between w-[57%] pb-4">
          {[
            'Architect',
            'Lawyer',
            'Painter',
            'Electrician',
            'Chinese Civil',
            'Julius Berger',
            'Web Developer',
            'Caterer',
          ].map((category, index) => (
            <div key={index}>
              <a
                href="/"
                className="bg-[#D9D9D9] px-[7px] py-1 font-Inter text-[11px] rounded font-bold"
              >
                {category}
              </a>
            </div>
          ))}
        </div>

        <div className="flex flex-wrap gap-4">
          {/* Dropdown Buttons */}
          {[
             { label: 'Category', id: 'category' },
            { label: 'Service Option', id: 'serviceOption' },
            { label: 'Budget', id: 'budget' },
            { label: 'Delivery Time', id: 'deliveryTime' },
            
          ].map((dropdown, index) => (
            <div key={index} className="relative">
              <div
                className="bg-[#0000] px-4 py-1 cursor-pointer flex items-center justify-between font-Inter text-[15px] rounded border border-[#FC8E08] font-bold"
                onClick={() => toggleDropdown(dropdown.id)}
              >
                <span>{dropdown.label}</span>
                <div className="w-[15px] ml-2">
                  <img src={arrow} alt="Dropdown Arrow" className="w-[70%] h-[7px]" />
                </div>
              </div>

              {/* Dropdown Menu */}
              {openDropdown === dropdown.id && (
                <div
                  id={dropdown.id}
                  className="rounded border-[1px] border-gray-300 bg-white absolute top-[110%] w-auto shadow-md z-10"
                >
                  <div className="cursor-pointer hover:bg-gray-300 px-4 py-2">
                    Option 1
                  </div>
                  <div className="cursor-pointer hover:bg-gray-300 px-4 py-2">
                    Option 2
                  </div>
                  <div className="cursor-pointer hover:bg-gray-300 px-4 py-2">
                    Option 3
                  </div>
                  <div className="cursor-pointer hover:bg-gray-300 px-4 py-2">
                    Option 4
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Suggested;
