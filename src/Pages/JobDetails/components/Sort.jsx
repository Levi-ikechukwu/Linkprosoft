import  { useState } from 'react';

const Sort = () => {

      const [openDropdown, setOpenDropdown] = useState(null);
    
      const toggleDropdown = (dropdownId) => {
        setOpenDropdown(openDropdown === dropdownId ? null : dropdownId);
      };
  return (
   <>
   
   </>
  )
}

export default Sort