import axios from "axios";
import { useContext } from "react";
import { useEffect } from "react";
import { useState } from "react";
import { createContext } from "react";
import { toast } from "react-toastify";

const UserContext = createContext();

const UserProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [signUpUserAs, setSignUpUserAs] = useState('');


    //fetching user functionality
    useEffect(() => {
        const fetchUser = async () => {
            try {
                const res = await axios.get("http://localhost:5020/api/auth/check-auth", {
                    withCredentials: true, // needed for cookie-based auth
                });

                setUser(res.data.user);

            } catch (err) {
                setUser(false);
            } finally {
                setLoading(false);
            }
        };

        fetchUser();
    }, []);

    //signup-as employer functionality
    const handleEmployer = user_type => setSignUpUserAs(prev => prev = user_type);

    //signup-as professional functionality
    const handleProfessional = user_type => setSignUpUserAs(prev => prev = user_type);

    // signup functionality
    const signup = async (formData) => {
        try {
            const res = await axios.post('http://localhost:5020/api/auth/register', formData, {
                withCredentials: true,
            });
            const { token, user } = res.data

            localStorage.setItem('token', token);


            setUser(user);
            if (res.data.success) {
                return { success: true, message: res.data.message, data: res.data.data.userType };
            } else {
                return { success: false, message: res.data.message };
            }

        } catch (error) {
            console.error(error.message);
        }
    }


    //login functionality
    const login = async (formData) => {
        try {
            const res = await axios.post('http://localhost:5020/api/auth/login', formData);
            const { token, user } = res.data

            localStorage.setItem("token", token);
            setUser(user);
            if(user){
                toast.success("Login successful!");
            } else{
                toast.warning('Invalid email or password');
            }

            if (user.userType === 'employer') {
                return { path: 'employer' }
            }

            if (user.userType === 'professional') {
                return { path: 'professional' }
            }

            setTimeout(() => {
            }, 1000)

        } catch (error) {
            console.error(error.message);
        }
    }


    //logout functionality
    const logout = async () => {
        try {
            const res = await axios.post('http://localhost:5020/api/auth/logout', {}, {
                withCredentials: true,
            });
            console.log(res);
            setUser(null);

        } catch (error) {
            console.error(error.message);
        }
    }

    return (
        <UserContext.Provider value={{
            user,
            signup,
            login,
            logout,
            signUpUserAs,
            handleEmployer,
            handleProfessional,
        }}>
            {children}
        </UserContext.Provider>
    )
}

export const useAuth = () => useContext(UserContext);
export default UserProvider;