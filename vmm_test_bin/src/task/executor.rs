use core::task::{Context, Poll, Waker};

use alloc::{collections::BTreeMap, sync::Arc, task::Wake};
use crossbeam_queue::ArrayQueue;

use super::{Task, TaskId};

const MAX_TASKS: usize = 100;

pub struct Executor {
    tasks: BTreeMap<TaskId, Task>,
    task_queue: Arc<ArrayQueue<TaskId>>,
    waker_cache: BTreeMap<TaskId, Waker>,
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            tasks: BTreeMap::new(),
            task_queue: Arc::new(ArrayQueue::new(MAX_TASKS)),
            waker_cache: BTreeMap::new(),
        }
    }

    pub fn spawn(&mut self, task: Task) {
        let tid = task.id;
        if self.tasks.insert(task.id, task).is_some() {
            panic!("task with same ID already spawned");
        }
        self.task_queue.push(tid).expect("task queue overflow");
    }

    pub fn run(&mut self) {
        while !self.tasks.is_empty() {
            self.run_ready_tasks();

            x86_64::instructions::interrupts::disable();
            if self.task_queue.is_empty() {
                x86_64::instructions::interrupts::enable_and_hlt();
            } else {
                x86_64::instructions::interrupts::enable();
            }
        }
    }

    pub fn run_ready_tasks(&mut self) {
        let Self {
            tasks,
            task_queue,
            waker_cache,
        } = self;

        while let Ok(tid) = task_queue.pop() {
            let task = match tasks.get_mut(&tid) {
                Some(t) => t,
                None => continue,
            };

            let waker = waker_cache
                .entry(tid)
                .or_insert_with(|| TaskWaker::new(tid, task_queue.clone()));

            let mut ctx = Context::from_waker(waker);

            match task.poll(&mut ctx) {
                Poll::Ready(()) => {
                    tasks.remove(&tid);
                    waker_cache.remove(&tid);
                }
                Poll::Pending => {}
            };
        }
    }
}

struct TaskWaker {
    task_id: TaskId,
    task_queue: Arc<ArrayQueue<TaskId>>,
}

impl TaskWaker {
    pub fn new(task_id: TaskId, task_queue: Arc<ArrayQueue<TaskId>>) -> Waker {
        Waker::from(Arc::new(TaskWaker {
            task_id,
            task_queue,
        }))
    }

    fn wake_task(&self) {
        self.task_queue
            .push(self.task_id)
            .expect("task queue overflow");
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_task();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_task()
    }
}
