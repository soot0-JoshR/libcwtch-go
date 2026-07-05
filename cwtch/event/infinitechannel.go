package event

/*
This package is taken from https://github.com/eapache/channels
as per their suggestion we are not importing the entire package and instead cherry picking and adapting what is needed

It is covered by the MIT License https://github.com/eapache/channels/blob/master/LICENSE
*/

// infiniteChannel implements the Channel interface with an infinite buffer between the input and the output.
type infiniteChannel struct {
	input, output chan Event
	length        chan int
	buffer        *infiniteQueue
}

func newInfiniteChannel() *infiniteChannel {
	ch := &infiniteChannel{
		input:  make(chan Event),
		output: make(chan Event),
		length: make(chan int),
		buffer: newInfinitQueue(),
	}
	go ch.infiniteBuffer()
	return ch
}
func (ch *infiniteChannel) In() chan<- Event {
	return ch.input
}

func (ch *infiniteChannel) Out() <-chan Event {
	return ch.output
}

func (ch *infiniteChannel) Len() int {
	return <-ch.length
}

func (ch *infiniteChannel) Close() {
	close(ch.input)
}

func (ch *infiniteChannel) infiniteBuffer() {
	var input, output chan Event
	var next Event
	input = ch.input

	for input != nil || output != nil {
		select {
		case elem, open := <-input:
			if open {
				ch.buffer.Add(elem)
			} else {
				input = nil
			}
		case output <- next:
			ch.buffer.Remove()
		case ch.length <- ch.buffer.Length():
		}

		if ch.buffer.Length() > 0 {
			output = ch.output
			next = ch.buffer.Peek()
		} else {
			output = nil
			//next = nil
		}
	}

	close(ch.output)
	close(ch.length)
}
