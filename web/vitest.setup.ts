// React refuses to treat `act()` as real unless it is told it is running in a
// test. Without this it prints "The current testing environment is not
// configured to support act(...)" and carries on -- updates are not reliably
// flushed, so an assertion can read the DOM from before the state change it was
// waiting for. A test that passes for that reason is worse than no test.
//
// Declared rather than imported from a package: this one global is the whole of
// what @testing-library's setup would do for us here, and the suite drives
// react-dom directly so it can perform the server render and the hydration as
// two separate steps.
declare global {
  // eslint-disable-next-line no-var
  var IS_REACT_ACT_ENVIRONMENT: boolean;
}

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

export {};
