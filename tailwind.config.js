/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bluecolor: '#006FA3',
        hrcolor: 'rgba(252, 142, 8, 0.7)',
        greycolor: 'rgba(0, 0, 0, 0.7)',
        greybg: '#E9F3EB',
        orangecolor: ' #D9D9D9',
        greencolor: ' rgba(35, 136, 58, 1)'
      },
      fontFamily: {
        Inter: ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}