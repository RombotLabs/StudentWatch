
# EduStream

EduStream is a web application designed to help educators provide students with curated access to YouTube videos.  
Built with Flask and SQLite, it enables seamless video sharing within a controlled environment.

## Features

- **User Authentication**: Secure login system for teachers and students.
- **Video Management**: Teachers can add, organize, and share YouTube video links.
- **Student Access**: Students can view assigned videos without leaving the platform.
- **Responsive Design**: Optimized for both desktop and mobile devices.

## Installation

### Prerequisites

- Python 3.8+
- pip (Python package installer)

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/RombotLabs/EduStream.git
   cd EduStream
   ```
   
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:

   ```bash
   python main.py
   ```

**IMPORTANT!!!**
Please chnage your secret key before you start the website!!!

The application will be accessible at [http://127.0.0.1:5000/](http://127.0.0.1:5000/).
If you change the last line from app.run() to app.run(host='0.0.0.0', port=5000)


## Usage

* **Teacher Login**: Use the credentials provided during setup to log in.
* **Add Videos**: Navigate to the 'Add Video' section to input YouTube URLs.
* **Student Access**: Students can view assigned videos upon logging in.

## Contributing

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes with clear messages.
4. Push to your branch and create a Pull Request.

## License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.

```
```
