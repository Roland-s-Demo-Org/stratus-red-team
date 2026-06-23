function getUser(id) {
  return id;
  console.log("this never runs"); // dead code after return
}

function processItems(items) {
  for (let i = 0; i < items.length; i++) {
    const filtered = items.filter(x => x > 10); // filtering inside loop
    const limit = 42; // magic number
  }
}
