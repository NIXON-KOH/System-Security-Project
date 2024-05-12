document.getElementById('toggle-webcam').addEventListener('click', function() {
    var videoExists = document.querySelector('.login-background video');
    if (videoExists) {
        videoExists.remove();
        document.getElementById('background-image').style.display = 'block';
    } else {
        var video = document.createElement('video');
        video.setAttribute('playsinline', '');
        video.setAttribute('autoplay', '');
        video.setAttribute('muted', '');
        video.style.width = '100%';
        video.style.height = '100%';

        var constraints = {
            audio: false,
            video: {
                facingMode: "user"
            }
        };

        console.log(document.getElementById('background-container'));
        document.getElementById('background-container').appendChild(video);


        navigator.mediaDevices.getUserMedia(constraints).then(function success(stream) {
            video.srcObject = stream;
            document.getElementById('background-image').style.display = 'none';
            document.getElementById('background-container').appendChild(video);
        }).catch(function(error) {
            console.error("Error accessing media devices.", error);
        });
    }
});

function epilepsy() {
    const colors = ['red', 'purple', 'blue', 'green', 'yellow', 'orange']; // Colors to flash
    let index = 0;
    let originalBodyBg = document.body.style.backgroundColor;

    const intervalId = setInterval(() => {
        document.body.style.backgroundColor = colors[index]; 
        index = (index + 1) % colors.length; 
    }, 500); // <--- set time where 100 = 0.1s

    const allElements = document.querySelectorAll('div, p');
    let originalOpacities = [];
    allElements.forEach((el, idx) => {
        originalOpacities.push(el.style.opacity); 
        if (idx % 2 === 0) { 
            el.style.opacity = 0;
        }
    });

    function revertChanges() {
        clearInterval(intervalId);
        document.body.style.backgroundColor = originalBodyBg; 
        allElements.forEach((el, idx) => {
            el.style.opacity = originalOpacities[idx];
        });
    }
    setTimeout(revertChanges, 10000); // <-- edit this to change time the function flashes for
}

document.getElementById('start-seizure').addEventListener('click', epilepsy);