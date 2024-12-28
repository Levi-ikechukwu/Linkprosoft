
import { Link } from 'react-router-dom'

const Error = () => {
  return (
    <div>
      <h1>Error: Page not found</h1>
      <Link to="/">Go back to Home page do not come here again</Link>
    </div>
  )
}

export default Error