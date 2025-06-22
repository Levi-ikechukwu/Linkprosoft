import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/User";
import Loader from "./Loader";

const ProtectedRoute = ({ children }) => {
    const { user, loading } = useAuth();

    if (loading) return <Loader />; // wait until we know user status

    return user ? children : <Navigate to="/login" />;
};

export default ProtectedRoute;