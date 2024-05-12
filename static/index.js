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
