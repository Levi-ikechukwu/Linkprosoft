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

    //fetching user
    useEffect(() => {
    const fetchUser = async () => {
            try {
                const res = await axios.get("http://localhost:5020/api/auth/check-auth", {
                    withCredentials: true,
                });
                setUser(res.data.user);
            } catch (err) {
                setUser(null);
                localStorage.removeItem("token");
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

    const signup = async (formData) => {
        try {
            const res = await axios.post('http://localhost:5020/api/auth/register', formData, {
                withCredentials: true,
            });
            const { user } = res.data

            if(user){
                setUser(user);
            }

            if (res.data.success) {
                return { success: true, message: res.data.message, user_type: res.data.user.userType };
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
            const { user } = res.data

            if (user) {
                toast.success(res.data.message);
                setUser(user);
            } else {
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

            toast.info(res.data.message);
            setUser(null);
            localStorage.removeItem('token');

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
            loading,
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