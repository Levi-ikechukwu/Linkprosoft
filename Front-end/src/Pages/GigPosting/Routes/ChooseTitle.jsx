const predefinedSkills = [
    "UI/UX Design",
    "Mobile App dev",
    "Figma",
    "Web Dev",
    "web design",
    "House wiring",
    "Catering",
    "Bricklaying",
    "Painting",
];

export default function ChooseTitle({ setIsActive }) {

    function handleNavigateForward() {
        setIsActive(prev => prev = 'skill-required')
    }

    return (
        <div className="w-full lg:w-[75%] xl:w-[75%] min-h-screen flex flex-col items-center px-4 md:px-20 lg:px-16 py-8 lg:py-10 place-self-end relative z-[10]">
            <div className="w-full lg:w-[90% mx-auto">
                {/* Title Section */}
                <div className="mb-8">
                    <h1 className="text-2xl md:text-3xl font-bold mb-2">Choose a strong title.</h1>
                    <p className="text-gray-600">The right title helps your Gigs post to stand out to the right candidates. It's the first thing that they’ll see.</p>
                </div>

                {/* Form Section */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12">
                    {/* Title Input */}
                    <div>
                        <label htmlFor="gig-title" className="block text-gray-700 font-medium mb-2">
                            Write a title for your Gigs post
                        </label>
                        <input
                            id="gig-title"
                            type="text"
                            placeholder="e.g. SEO specialist needed"
                            className="w-full border border-gray-300 rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                    </div>

                    {/* Example Titles */}
                    <div>
                        <h3 className="text-gray-700 font-medium mb-2">Example titles</h3>
                        <ul className="list-disc list-inside text-gray-600 space-y-1">
                            <li>Build a user friendly e-commerce site using Framer</li>
                            <li>SEO specialist needed</li>
                        </ul>
                    </div>
                </div>

                {/* Navigation Buttons */}
                <div className="flex justify-between items-center mt-[5rem] ">
                    <button disabled={true} className="border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-100 w-auto">
                        Back
                    </button>
                    <button onClick={handleNavigateForward} className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition">
                        Next: Skills
                    </button>
                </div>

                {/* Progress Bar */}
                <div className="mt-6 flex place-content-end min-h-full">
                    <div className="h-1 w-full bg-gray-300 rounded">
                        <div className="h-full bg-blue-500 w-1/5 rounded"></div>
                    </div>
                </div>
            </div>
        </div>
    );
}
