console.log("meow")

document.addEventListener('DOMContentLoaded', function() {

    function epilepsy() {
    console.log("hellos")
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
